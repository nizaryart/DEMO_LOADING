"""What the Google and Azure cloud CLIs and railway do (M2.2b2b): gcloud,
gsutil, az, azcopy, railway - the second half of the cloud family, built on
cloud_ops.py's helpers and labels (storage: / cred: / secret: / queue: /
cloud:, plus volume: for railway's volumes).

WHAT IT CLAIMS, AND WHAT IT DOES NOT. The safety property of git_ops.py: an
operation or an option this module does not list is `uncovered`, and today's
text path decides the line unchanged. Escalating kinds and reads are claimed;
creations, starts, remote shells (ssh, connect, run), the tools' own login /
configuration (gcloud auth / config / get-credentials, az login / account /
config / aks get-credentials, railway link / login) and anything that writes
files the line does not name (exports) are not. A creation that carries data
on its own line (metadata, headers, content fields) is not claimed either
(the M2.2b1 payload rule).

GRAMMARS ARE VERIFIED (2026-10-07) on the releases current that day - gcloud
588.0.0 with gsutil 5.37, azure-cli 2.91.0, azcopy 10.32.8, railway 5.63.4 -
from the tools' own data and with no credentials (and, after an incident
that day, never against a real endpoint):
  - gcloud: global flags anywhere; an unknown flag before the command is
    refused; -h / --help print help; no abbreviation of commands. The verb
    table and the six group names that start like a verb come from gcloud's
    own command tree (17,379 commands). `alpha` / `beta` are release tracks;
    `deploy` at the top is the Cloud Deploy group, not a verb.
  - gsutil: options before the command (getopt 'dDvo:?h:i:u:mq'), then each
    command's own getopt string, and parsing STOPS at the first argument
    (`rm gs://b/x -r` takes `-r` as a path). `cp -n` is no-clobber, `rsync -n`
    is a dry run. Command aliases from its source.
  - az: options are refused before or between the command words, so the
    command is the leading words and the operation is the last of them.
    From az's source: `storage blob upload` / `upload-batch` refuse an
    existing blob unless `--overwrite`; `blob download` overwrites a local
    file unless `--overwrite false`; `download-batch` does not unless
    `--overwrite`; `copy start` always overwrites. `az rest` is decided by
    `--method` (default get); `--output-file` writes a local file.
  - azcopy: options anywhere (cobra); one-letter aliases (`c`, `r`, `s`);
    `--overwrite` defaults to true; `--dry-run`; `--delete-destination`.
  - railway: the command, then a group's action; `-h` / `-V` only global.
"""
from __future__ import annotations

from typing import Dict, FrozenSet, List, Optional, Tuple

from ..model import Word
from .cloud_ops import READ, _local, _reach, _split
from .effects import CREATE, DELETE, OVERWRITE, RUN, SEND, SERVICE_KEEP, SERVICE_LOSS

# ---------------------------------------------------------------- shared verbs

_READ_W = frozenset({"list", "describe", "show", "get", "search", "lookup", "check", "validate",
                     "detect", "wait", "read", "tail", "exists"})
_DELETE_W = frozenset({"delete", "remove", "purge", "revoke"})
_OVERWRITE_W = frozenset({"update", "set", "add", "reset", "apply", "replace", "detach", "attach",
                          "move", "rename", "rollback", "upgrade", "enable", "disable", "resize",
                          "patch", "cancel", "abandon", "deny", "approve", "reject", "migrate",
                          "failover", "promote", "switchover", "import", "regenerate", "renew",
                          "swap", "assign", "unassign", "deploy"})
_LOSS_W = frozenset({"stop", "suspend", "pause", "deallocate"})
_SEND_W = frozenset({"publish", "send"})
_RUN_W = frozenset({"execute", "call", "invoke"})


def _verb_kind(word: str) -> Optional[str]:
    p = word.split("-")[0]
    if p in _READ_W:
        return READ
    if p in _DELETE_W:
        return DELETE
    if p in _OVERWRITE_W:
        return OVERWRITE
    if p in _LOSS_W:
        return SERVICE_LOSS
    if p in _SEND_W:
        return SEND
    if p in _RUN_W:
        return RUN
    return None


def _surface(tool: str, group: str, extra: str = "") -> str:
    tail = f"{tool}:{group}{extra}"
    if group in ("storage",):
        return f"storage:{tail}"
    if group in ("iam", "role", "ad"):
        return f"cred:{tail}"
    if group in ("secrets", "keyvault"):
        return f"secret:{tail}"
    if group in ("pubsub", "servicebus", "eventhubs", "eventhub"):
        return f"queue:{tail}"
    return f"cloud:{tail}"


def _sides(w, inv, state, tool: str, src: Word, dst: Word, remote, label, kind_remote: str,
           local_how: Optional[str], words: List[Word], whole: bool, moves: bool) -> None:
    """A transfer: the destination's side decides; a move also loses its source."""
    if remote(dst):
        _reach(w, inv, label(dst), kind_remote, words, tool)
    elif dst.value != "-" and local_how is not None:
        _local(w, inv, state, dst, local_how, tool, whole=whole)
    if moves:
        if remote(src):
            _reach(w, inv, label(src), DELETE, words, tool)
        elif src.value != "-":
            _local(w, inv, state, src, DELETE, tool, whole=whole)


def _hidden(words: List[Word], remote) -> bool:
    return any(p.expands and not remote(p) for p in words)


# ---------------------------------------------------------------- gcloud

_GC_VALUES = frozenset({"--access-token-file", "--account", "--billing-project", "--configuration",
                        "--flags-file", "--flatten", "--format", "--impersonate-service-account",
                        "--project", "--trace-token", "--verbosity"})
_GC_FLAGS = frozenset({"--log-http", "--no-log-http", "--quiet", "-q", "--user-output-enabled",
                       "--no-user-output-enabled"})
_GC_TRACKS = frozenset({"alpha", "beta"})
# Group names that start like a verb but hold commands (gcloud's own tree).
# update / import / migrate / upgrade are groups too, and keep their kind.
_GC_VERBLIKE_GROUPS = frozenset({"add-job", "import-jobs", "migrate-config", "patch-deployments",
                                 "patch-jobs", "resize-requests"})
_GC_UNCLAIMED = frozenset({"get-credentials", "configure-docker"})
_GC_UNCLAIMED_GROUPS = frozenset({"auth", "config", "components", "init", "info", "help",
                                  "feedback", "survey", "topic", "cheat-sheet", "interactive"})
_GCS_DATA = frozenset({"--additional-headers", "--content-disposition", "--content-encoding",
                       "--content-language", "--content-md5", "--content-type", "--custom-metadata",
                       "--update-custom-metadata", "--remove-custom-metadata",
                       "--clear-custom-metadata"})


def _gs(word: Word) -> bool:
    return word.value.startswith("gs://")


def _gs_label(tool: str):
    return lambda p: f"storage:{tool}:gs://" + p.value[5:].split("/", 1)[0]


def gcloud(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    if any(a.value in ("-h", "--help") and not a.expands for a in args):
        return                                                  # VERIFIED: help
    if any(a.value == "--version" and not a.expands for a in args):
        return
    path: List[Word] = []
    after: List[Word] = []
    verb = None
    i = 0
    while i < len(args):
        a = args[i]
        v = a.value
        if verb is not None:
            after.append(a)
            i += 1
            continue
        if v.startswith("-") and not a.expands:
            name = v.partition("=")[0]
            if name in _GC_VALUES:
                i += 1 if "=" in v else 2
                continue
            if name in _GC_FLAGS:
                i += 1
                continue
            if "=" in v:
                i += 1                                          # a value glued on: its arity is known
                continue
            w.impact.not_covered("gcloud (option)")             # VERIFIED: refused, or its arity unknown
            return
        if a.expands:
            w.impact.not_understood(inv.text, "a gcloud command named by an expansion")
            return
        if not path and v in _GC_TRACKS:
            i += 1
            continue
        if v in _GC_UNCLAIMED or (not path and v in _GC_UNCLAIMED_GROUPS):
            return w.impact.not_covered(f"gcloud {v}")
        if len(path) == 1 and path[0].value == "storage" and v in _GCS_OPS:
            return _gcloud_storage(w, inv, state, v, _gc_strip(args[i + 1:]), tool)
        if (not path and v == "deploy") or v in _GC_VERBLIKE_GROUPS or _verb_kind(v) is None:
            path.append(a)
            i += 1
            continue
        verb = v
        i += 1
    if verb is None:
        # No listed verb. The words met may hold arguments too (a word that is
        # not a verb is read as a group), so the marker names the top group.
        if path:
            w.impact.not_covered(f"gcloud {path[0].value} (verb not listed)")
        return
    group = path[0].value if path else ""
    kind = _verb_kind(verb)
    _reach(w, inv, _surface("gcloud", group), kind, after, tool)


# gcloud storage cp / mv / rsync / rm options (gcloud's own tree; short forms
# from their --help).
_GCS_VALUES = frozenset({
    "--additional-headers", "--cache-control", "--canned-acl", "--content-disposition",
    "--content-encoding", "--content-language", "--content-md5", "--content-type",
    "--custom-contexts", "--custom-contexts-file", "--custom-metadata", "--custom-time",
    "--decryption-keys", "--encryption-key", "--exclude", "--gzip-in-flight", "--gzip-local",
    "--if-generation-match", "--if-metageneration-match", "--manifest-path", "--predefined-acl",
    "--remove-custom-contexts", "--remove-custom-metadata", "--retain-until", "--retention-mode",
    "--storage-class", "--update-custom-contexts", "--update-custom-metadata", "-a"})
_GCS_FLAGS = frozenset({
    "--all-versions", "--checksums-only", "--clear-custom-contexts", "--clear-custom-metadata",
    "--continue-on-error", "--daisy-chain", "--delete-unmatched-destination-objects",
    "--do-not-decompress", "--dry-run", "--exclude-managed-folders", "--gzip-in-flight-all",
    "--gzip-local-all", "--ignore-symlinks", "--include-managed-folders", "--no-clobber",
    "--preserve-acl", "--no-preserve-acl", "--preserve-posix", "--preserve-symlinks",
    "--print-created-message", "--read-paths-from-stdin", "--recursive",
    "--skip-if-dest-has-newer-mtime", "--skip-unsupported", "-n", "-I", "-r", "-R", "-p"})
_GCS_OPS = frozenset({"cp", "mv", "rsync", "rm", "ls", "cat", "du", "hash", "sign-url"})


def _gc_strip(words: List[Word]) -> List[Word]:
    """The words after a gcloud command, its global options removed."""
    out, i = [], 0
    while i < len(words):
        v = words[i].value
        name = v.partition("=")[0]
        if name in _GC_VALUES:
            i += 1 if "=" in v else 2
            continue
        if name in _GC_FLAGS:
            i += 1
            continue
        out.append(words[i])
        i += 1
    return out


def _gcloud_storage(w, inv, state, op: str, rest: List[Word], tool: str) -> None:
    """gcloud storage cp / mv / rsync / rm (and the reads): both sides."""
    if op in ("ls", "cat", "du", "hash", "sign-url"):
        return
    pos, got, bad = _split(rest, _GCS_VALUES, _GCS_FLAGS)
    if bad is not None:
        return w.impact.not_covered("gcloud storage (option)")
    label = _gs_label("gcloud")
    if op == "rm":
        if "--read-paths-from-stdin" in got or "-I" in got:
            return _reach(w, inv, "storage:gcloud:gs", DELETE, rest, tool)
        remote = [p for p in pos or [] if _gs(p)]
        return _reach(w, inv, label(remote[0]) if remote else "storage:gcloud:gs", DELETE, rest, tool)
    if "--dry-run" in got:
        return
    pos = pos or []
    if len(pos) != 2 or _hidden(pos[-1:] if op != "mv" else pos, _gs):
        w.impact.not_understood(inv.text, f"the source and destination of gcloud storage {op}")
        return
    src, dst = pos
    data = bool(_GCS_DATA & set(got))
    if op == "rsync" and "--delete-unmatched-destination-objects" in got:
        kind, how = DELETE, DELETE
    elif "--no-clobber" in got or "-n" in got:              # VERIFIED: no-clobber
        if data and _gs(dst):
            return w.impact.not_covered(f"gcloud storage {op} (data on the line)")
        kind, how = CREATE, None
    else:
        kind, how = OVERWRITE, OVERWRITE
    _sides(w, inv, state, tool, src, dst, _gs, label, kind, how, rest,
           whole=op == "rsync" or "--recursive" in got or "-r" in got or "-R" in got,
           moves=op == "mv")


# ---------------------------------------------------------------- gsutil

_GSUTIL_GLOBAL = "dDvo:?h:i:u:mq"
_GSUTIL_GLOBAL_LONG_VALUES = frozenset({"--impersonate-service-account", "--trace-token",
                                        "--perf-trace-token"})
_GSUTIL_GLOBAL_LONG_FLAGS = frozenset({"--debug", "--detailedDebug", "--version", "--option",
                                       "--help", "--header", "--multithreaded", "--quiet",
                                       "--testexceptiontraces"})
_GSUTIL_ALIASES = {"del": "rm", "delete": "rm", "remove": "rm", "deletebucket": "rb",
                   "removebucket": "rb", "removebuckets": "rb", "rmdir": "rb", "move": "mv",
                   "ren": "mv", "rename": "mv", "copy": "cp", "dir": "ls", "list": "ls",
                   "concat": "compose", "ver": "version", "setheader": "setmeta",
                   "signedurl": "signurl", "queryauth": "signurl", "getacl": "acl get",
                   "setacl": "acl set", "chacl": "acl ch", "getdefacl": "defacl get",
                   "setdefacl": "defacl set", "chdefacl": "defacl ch", "getcors": "cors get",
                   "setcors": "cors set", "getversioning": "versioning get",
                   "setversioning": "versioning set", "getwebcfg": "web get",
                   "setwebcfg": "web set", "getlogging": "logging get",
                   "enablelogging": "logging set", "disablelogging": "logging set",
                   "lifecycleconfig": "lifecycle", "?": "help", "man": "help"}
_GSUTIL_SUB = {"rm": "afIrR", "rb": "f", "cp": "a:AcDeIL:MNnpPrRs:tUvz:Zj:J",
               "mv": "a:AcDeIL:MNnpPrRs:tUvz:Zj:J", "rsync": "a:cCdenpPriRuUx:y:j:J",
               "setmeta": "h:rR", "rewrite": "fkIrROs:", "compose": "", "hmac": "ae:lp:s:u:"}
_GSUTIL_READ = frozenset({"ls", "cat", "du", "hash", "stat", "version", "help", "signurl"})
_GSUTIL_CONFIGS = frozenset({"acl", "defacl", "cors", "lifecycle", "logging", "versioning", "web",
                             "label", "iam", "kms", "notification", "retention", "requesterpays",
                             "defstorageclass", "autoclass", "bucketpolicyonly", "pap", "rpo", "ubla"})


def _getopt(words: List[Word], spec: str) -> Tuple[Dict[str, Optional[Word]], List[Word], Optional[str]]:
    """POSIX getopt: options until the first non-option word. (opts, rest, bad)."""
    opts: Dict[str, Optional[Word]] = {}
    i = 0
    while i < len(words):
        a = words[i]
        v = a.value
        if a.expands or not v.startswith("-") or v == "-":
            break
        if v == "--":
            i += 1
            break
        if v.startswith("--"):
            name, eq, glued = v.partition("=")
            if name in _GSUTIL_GLOBAL_LONG_VALUES:
                if not eq:
                    i += 1
            elif name not in _GSUTIL_GLOBAL_LONG_FLAGS:
                return opts, words[i:], name                    # VERIFIED: refused
            opts[name] = None
            i += 1
            continue
        j = 1
        while j < len(v):
            ch = v[j]
            k = spec.find(ch)
            if k < 0:
                return opts, words[i:], "-" + ch
            if k + 1 < len(spec) and spec[k + 1] == ":":
                if j + 1 < len(v):
                    opts["-" + ch] = Word(a.raw, v[j + 1:], a.start, a.end)
                elif i + 1 < len(words):
                    opts["-" + ch] = words[i + 1]
                    i += 1
                else:
                    return opts, [], "-" + ch
                break
            opts["-" + ch] = None
            j += 1
        i += 1
    return opts, words[i:], None


def gsutil(w, inv, parsed, state, tool) -> None:
    gopts, rest, bad = _getopt(list(inv.argv[1:]), _GSUTIL_GLOBAL)
    if bad is not None:
        return w.impact.not_covered("gsutil (option)")
    if "-v" in gopts or "--version" in gopts or "-?" in gopts or "--help" in gopts or not rest:
        return
    if rest[0].expands:
        w.impact.not_understood(inv.text, "a gsutil command named by an expansion")
        return
    cmd = _GSUTIL_ALIASES.get(rest[0].value, rest[0].value)
    sub_action = None
    if " " in cmd:
        cmd, sub_action = cmd.split(" ", 1)
    args = rest[1:]
    label = _gs_label("gsutil")
    if cmd in _GSUTIL_READ:
        return
    if cmd in _GSUTIL_CONFIGS:
        action = sub_action or (args[0].value if args and not args[0].expands else None)
        if action == "get":
            return
        if action is None:
            return w.impact.not_covered(f"gsutil {cmd}")
        remote = [p for p in args if _gs(p)]
        return _reach(w, inv, label(remote[0]) if remote else "storage:gsutil:gs", OVERWRITE, args, tool)
    if cmd == "hmac":
        action = args[0].value if args and not args[0].expands else None
        if action in ("get", "list"):
            return
        if action in ("delete", "update"):
            return _reach(w, inv, "cred:gsutil:hmac", DELETE if action == "delete" else OVERWRITE,
                          args, tool)
        return w.impact.not_covered(f"gsutil hmac {action}")
    if cmd not in _GSUTIL_SUB:
        return w.impact.not_covered(f"gsutil {cmd}")
    opts, ops, bad = _getopt(args, _GSUTIL_SUB[cmd])
    if bad is not None:
        return w.impact.not_covered(f"gsutil {cmd} (option)")
    if cmd in ("rm", "rb", "setmeta", "rewrite", "compose"):
        remote = [p for p in ops if _gs(p)]
        kind = DELETE if cmd in ("rm", "rb") else OVERWRITE
        return _reach(w, inv, label(remote[-1]) if remote else "storage:gsutil:gs", kind, args, tool)
    if cmd == "rsync" and "-n" in opts:
        return                                                  # VERIFIED: rsync -n = dry run
    if "-I" in opts:
        w.impact.not_understood(inv.text, f"the sources gsutil {cmd} reads from stdin")
        return
    if len(ops) < 2 or _hidden(ops if cmd == "mv" else ops[-1:], _gs):
        w.impact.not_understood(inv.text, f"the source and destination of gsutil {cmd}")
        return
    srcs, dst = ops[:-1], ops[-1]
    if cmd == "rsync" and "-d" in opts:
        kind, how = DELETE, DELETE
    elif cmd in ("cp", "mv") and "-n" in opts:                  # VERIFIED: cp -n = no-clobber
        if "-h" in gopts and _gs(dst):
            return w.impact.not_covered(f"gsutil {cmd} (data on the line)")
        kind, how = CREATE, None
    else:
        kind, how = OVERWRITE, OVERWRITE
    whole = cmd == "rsync" or "-r" in opts or "-R" in opts
    for s in srcs:
        _sides(w, inv, state, tool, s, dst, _gs, label, kind, how, args, whole=whole,
               moves=cmd == "mv")


# ---------------------------------------------------------------- az

_AZ_UNCLAIMED_GROUPS = frozenset({"login", "logout", "account", "config", "extension", "upgrade",
                                  "self-test", "init", "interactive", "feedback", "find", "survey",
                                  "bicep", "cloud", "ssh", "version", "alias", "next"})
_AZ_UNCLAIMED = frozenset({"get-credentials", "ssh", "connect", "exec", "console", "browse",
                           "tunnel", "create-remote-connection", "export"})
_AZ_STORAGE_DATA = frozenset({"--metadata", "--content-type", "--content-encoding",
                              "--content-language", "--content-disposition", "--content-cache-control",
                              "--content-cache", "--content-md5", "--tags"})


def _az_opt(rest: List[Word], *names: str) -> Tuple[bool, Optional[Word]]:
    for i, a in enumerate(rest):
        v = a.value
        name, eq, glued = v.partition("=")
        if name in names and not a.expands:
            if eq:
                return True, Word(a.raw, glued, a.start, a.end, expands=a.expands)
            nxt = rest[i + 1] if i + 1 < len(rest) else None
            if nxt is not None and not nxt.value.startswith("-"):
                return True, nxt
            return True, None
    return False, None


def _az_true(present: bool, val: Optional[Word]) -> bool:
    """A three-state flag: bare = true; `false` / `no` / `0` = false."""
    if not present:
        return False
    return val is None or val.value.lower() not in ("false", "no", "0", "off")


def az(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    path: List[Word] = []
    for a in args:
        if a.value.startswith("-") or a.expands:
            break
        path.append(a)
    rest = args[len(path):]
    if any(a.value in ("-h", "--help") and not a.expands for a in rest) or not path:
        return
    if any(a.expands for a in args[:len(path) + 1] if not a.value.startswith("-")) and len(path) < 2:
        w.impact.not_understood(inv.text, "an az command named by an expansion")
        return
    group, leaf = path[0].value, path[-1].value
    if group in _AZ_UNCLAIMED_GROUPS or leaf in _AZ_UNCLAIMED:
        return w.impact.not_covered(f"az {' '.join(p.value for p in path)}")
    if group == "rest":
        present, m = _az_opt(rest, "--method", "-m")
        method = (m.value.lower() if m is not None and not m.expands else ("get" if not present else None))
        out_present, out = _az_opt(rest, "--output-file")
        if out_present and out is not None:
            _local(w, inv, state, out, OVERWRITE, "az")
        kind = {"get": READ, "head": READ, "options": READ, "delete": DELETE,
                "put": OVERWRITE, "patch": OVERWRITE, "post": SEND}.get(method or "")
        if kind is None:
            w.impact.not_understood(inv.text, "the method az rest sends")
            return
        return _reach(w, inv, "cloud:az:rest", kind, rest, tool)
    if group == "storage":
        return _az_storage(w, inv, state, [p.value for p in path], rest, tool)
    kind = _verb_kind(leaf)
    if kind is None:
        return w.impact.not_covered(f"az {' '.join(p.value for p in path)}")
    if leaf.startswith("get-credentials"):
        return w.impact.not_covered(f"az {' '.join(p.value for p in path)}")
    second = path[1].value if len(path) > 2 else ""
    g = "keyvault" if group == "keyvault" and second in ("secret", "key", "certificate") else group
    _reach(w, inv, _surface("az", g), kind, rest, tool)


def _az_storage(w, inv, state, path: List[str], rest: List[Word], tool: str) -> None:
    leaf = path[-1]
    account = _az_opt(rest, "--account-name")[1]
    label = "storage:az:" + (account.raw if account is not None else "storage")
    data = any(a.value.partition("=")[0] in _AZ_STORAGE_DATA for a in rest)
    if "--dryrun" in [a.value for a in rest]:
        return                                                  # the batch commands: a summary only
    if path[1:3] == ["blob", "upload"] or path[1:3] == ["blob", "upload-batch"]:
        if _az_true(*_az_opt(rest, "--overwrite")):
            return _reach(w, inv, label, OVERWRITE, rest, tool)
        if data:
            return w.impact.not_covered(f"az storage blob {leaf} (data on the line)")
        return _reach(w, inv, label, CREATE, rest, tool)       # VERIFIED: refuses an existing blob
    if path[1:3] == ["blob", "download"]:
        present, f = _az_opt(rest, "--file", "-f")
        ow_present, ow = _az_opt(rest, "--overwrite")
        if f is not None and (not ow_present or _az_true(ow_present, ow)):
            _local(w, inv, state, f, OVERWRITE, "az")          # VERIFIED: default overwrite
        return
    if path[1:3] == ["blob", "download-batch"]:
        present, d = _az_opt(rest, "--destination", "-d")
        if d is not None and _az_true(*_az_opt(rest, "--overwrite")):
            _local(w, inv, state, d, OVERWRITE, "az", whole=True)
        return
    if path[1:3] == ["blob", "sync"]:
        present, dd = _az_opt(rest, "--delete-destination")
        deletes = present and (dd is None or dd.value.lower() in ("true", "prompt"))
        return _reach(w, inv, label, DELETE if deletes else OVERWRITE, rest, tool)
    if path[1:3] == ["blob", "copy"]:
        if leaf in ("start", "start-batch"):
            return _reach(w, inv, label, OVERWRITE, rest, tool)  # VERIFIED: always overwrites
    kind = _verb_kind(leaf)
    if leaf in ("download", "download-batch", "upload", "upload-batch") or kind is None:
        return w.impact.not_covered("az " + " ".join(path))
    _reach(w, inv, label, kind, rest, tool)


# ---------------------------------------------------------------- azcopy

_AZC_VALUES = frozenset({
    "--blob-tags", "--blob-type", "--block-blob-tier", "--block-size-mb", "--cache-control",
    "--cap-mbps", "--check-md5", "--compare-hash", "--content-disposition", "--content-encoding",
    "--content-language", "--content-type", "--cpk-by-name", "--delete-destination",
    "--delete-snapshots", "--exclude-attributes", "--exclude-blob-type", "--exclude-container",
    "--exclude-path", "--exclude-pattern", "--exclude-regex", "--from-to", "--hardlinks",
    "--include-after", "--include-attributes", "--include-before", "--include-path",
    "--include-pattern", "--include-regex", "--list-of-files", "--list-of-versions",
    "--local-hash-storage-mode", "--log-level", "--metadata", "--output-level", "--output-type",
    "--overwrite", "--page-blob-tier", "--permanent-delete", "--posix-properties-style",
    "--put-blob-size-mb", "--rehydrate-priority", "--s2s-handle-invalid-metadata", "--trailing-dot",
    "--trusted-microsoft-suffixes"})
_AZC_FLAGS = frozenset({
    "--as-subdir", "--backup", "--check-length", "--check-version", "--cpk-by-value", "--decompress",
    "--disable-auto-decoding", "--dry-run", "--follow-symlinks", "--force-if-read-only",
    "--hash-meta-dir", "--help", "--include-directory-stub", "--include-root", "--mirror-mode",
    "--no-guess-mime-type", "--preserve-info", "--preserve-last-modified-time", "--preserve-owner",
    "--preserve-permissions", "--preserve-posix-properties", "--preserve-symlinks", "--put-md5",
    "--recursive", "--s2s-detect-source-changed", "--s2s-preserve-access-tier",
    "--s2s-preserve-blob-tags", "--s2s-preserve-properties", "-h", "--skip-version-check"})
_AZC_ALIASES = {"cp": "copy", "c": "copy", "rm": "remove", "r": "remove", "sc": "sync", "s": "sync"}
_AZC_DATA = frozenset({"--metadata", "--blob-tags", "--content-type", "--content-encoding",
                       "--content-language", "--content-disposition", "--cache-control"})


def _http(word: Word) -> bool:
    return word.value.startswith(("https://", "http://"))


def _host_label(word: Word) -> str:
    return "storage:azcopy:" + word.value.split("://", 1)[1].split("/", 1)[0]


def azcopy(w, inv, parsed, state, tool) -> None:
    pos, got, bad = _split(list(inv.argv[1:]), _AZC_VALUES, _AZC_FLAGS)
    if bad is not None:
        return w.impact.not_covered("azcopy (option)")
    if not pos or "--help" in got or "-h" in got:
        return
    if pos[0].expands:
        w.impact.not_understood(inv.text, "an azcopy command named by an expansion")
        return
    cmd = _AZC_ALIASES.get(pos[0].value, pos[0].value)
    ops = pos[1:]
    if cmd in ("list", "env", "doc", "completion", "help"):
        return
    if cmd == "jobs":
        action = ops[0].value if ops and not ops[0].expands else None
        if action in ("list", "show"):
            return
        return w.impact.not_covered(f"azcopy jobs {action}")
    if "--dry-run" in got:
        return
    if cmd in ("remove", "set-properties"):
        if not ops or not _http(ops[0]):
            return w.impact.not_covered(f"azcopy {cmd}")
        return _reach(w, inv, _host_label(ops[0]), DELETE if cmd == "remove" else OVERWRITE,
                      inv.argv[1:], tool)
    if cmd not in ("copy", "sync"):
        return w.impact.not_covered(f"azcopy {cmd}")
    if len(ops) != 2 or _hidden(ops[-1:], _http):
        w.impact.not_understood(inv.text, f"the source and destination of azcopy {cmd}")
        return
    src, dst = ops
    if cmd == "sync":
        dd = got.get("--delete-destination")
        deletes = dd is not None and dd.value.lower() in ("true", "prompt")
        kind = how = DELETE if deletes else OVERWRITE
    else:
        ow = got.get("--overwrite")
        if ow is not None and ow.value.lower() == "false":
            if _http(dst) and _AZC_DATA & set(got):
                return w.impact.not_covered("azcopy copy (data on the line)")
            kind, how = CREATE, None
        else:
            kind = how = OVERWRITE                              # VERIFIED: default true
    _sides(w, inv, state, tool, src, dst, _http, _host_label, kind, how, inv.argv[1:],
           whole=cmd == "sync" or "--recursive" in got, moves=False)


# ---------------------------------------------------------------- railway

_RW_READ = frozenset({"list", "status", "whoami", "logs", "docs", "open", "usage", "metrics", "info",
                      "files", "browse", "help"})
_RW_GROUPS = frozenset({"volume", "variable", "environment", "service", "project", "bucket",
                        "deployment", "domain"})


def railway(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    if any(a.value in ("-h", "--help", "-V", "--version") and not a.expands for a in args):
        return
    pos: List[Word] = []
    for a in args:
        if a.value.startswith("-"):
            if not pos:
                return w.impact.not_covered("railway (option)")
            if len(pos) == 1 and pos[0].value in _RW_GROUPS:
                return w.impact.not_covered(f"railway {pos[0].value} (option)")
            break
        pos.append(a)
        if len(pos) == 2:
            break
    if not pos:
        return
    if any(p.expands for p in pos):
        w.impact.not_understood(inv.text, "a railway command named by an expansion")
        return
    cmd = pos[0].value
    action = pos[1].value if len(pos) > 1 and cmd in _RW_GROUPS else None
    prefix = {"volume": "volume", "variable": "secret"}.get(cmd, "cloud")
    label = f"{prefix}:railway:{cmd}"
    if cmd in _RW_READ or action in _RW_READ or action == "credentials":
        return
    if cmd in ("delete", "down") or action in ("delete", "detach"):
        return _reach(w, inv, label, DELETE, args, tool)
    if cmd in ("up", "redeploy", "deploy") or action in ("set", "edit", "update", "attach",
                                                         "rename", "source", "redeploy", "up",
                                                         "config"):
        return _reach(w, inv, label, OVERWRITE, args, tool)
    if cmd == "restart" or action == "restart":
        return _reach(w, inv, label, SERVICE_KEEP, args, tool)
    if cmd in _RW_GROUPS and action is None:
        return
    w.impact.not_covered(f"railway {cmd}" + (f" {action}" if action else ""))


# ---------------------------------------------------------------- entry

_TOOLS = {"gcloud": gcloud, "gsutil": gsutil, "az": az, "azcopy": azcopy, "railway": railway}


def cloud2(w, inv, parsed, state, tool) -> None:
    _TOOLS[tool](w, inv, parsed, state, tool)
