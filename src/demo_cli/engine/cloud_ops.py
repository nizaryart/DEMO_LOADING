"""What a cloud CLI does, in the engine's effect language (M2.2b2a): aws, s3cmd,
rclone and mc - the cloud APIs and the S3-style object stores.

Each changes things no local copy restores, and each also moves files between
the cloud and THIS machine. Both sides are modelled: a remote change is
`reach(label, kind)` and policy.py decides it; a local file a download writes
or a move removes goes through the world primitives, so it is captured.

WHAT IT CLAIMS, AND WHAT IT DOES NOT. The safety property of git_ops.py: an
operation or an option this module does not list is reported as `uncovered`,
and today's text path decides the line unchanged. Not claimed ON PURPOSE:
  - CREATIONS and starts on the cloud APIs (`create-*`, `run-*`, `start-*`):
    their parameters can carry code the cloud runs (`--user-data`, a build
    spec) that this engine does not read, and today's path reads that text
    (the M2.2b1 lesson). Escalating kinds and reads ARE claimed;
  - the aws CLI's own local commands (`configure set`, `eks
    update-kubeconfig`, `codeartifact login`, the wizards, `ssh` / `socks`):
    they write tool configuration or open a remote shell (M2.2d, M2.2b4);
  - rclone and mc commands that serve, mount, run a UI or a remote-control
    API, or touch their own configuration; `mc find --exec`; `mc admin`.

A REMOTE CHANGE: labels name the surface (policy._LABEL_SURFACES):
  storage:<tool>:<bucket or remote>  -> object_storage
  cred:aws:iam                       -> credential_rotation
  secret:aws:<service>               -> secret_write
  queue:aws:<service>                -> message_queue
  cloud:aws:<service>                -> cloud_resource_delete
An upload that may replace objects is OVERWRITE (ruling R2, 2026-10-07); with
a VERIFIED no-overwrite flag it is CREATE: aws `--no-overwrite`, s3cmd
`--skip-existing`, rclone `--ignore-existing` / `--immutable`. A sync that
deletes what the source lacks is DELETE.

THE aws API, by verb. The operation's first word decides (ruling R3: a read
the old regexes escalated - any `aws iam`, any word "delete" - becomes ALLOW).
The prefixes below are the ones the CLI's own command index uses across its
19,531 operations; an operation whose prefix is not listed is uncovered.

GRAMMARS ARE VERIFIED (2026-10-07) against the releases current that day -
aws-cli 2.37.10 and 1.46.1, s3cmd 2.4.0, rclone 1.75.1, mc
RELEASE.2025-08-13T08-35-41Z (built from that tag) - with no credentials, and
rclone on its in-memory backend and scratch folders:
  - aws: global options stand anywhere and may be abbreviated (`--prof`);
    `-h` is an error and the word `help` prints help; `--dry-run` either
    simulates (EC2) or is refused as unknown - nothing runs either way; an
    unknown option before the operation is refused. The operation lists, the
    local commands and the 66 operations that write an `outfile` come from
    aws v2's own command index (ac.index) and the service models.
  - s3cmd: options stand anywhere (optparse); `-n` / `--dry-run` is honoured
    ONLY by del / rm, get, put, restore, sync and the set / del policy
    commands (rb, cp, mv, expire ... act anyway); get skips an existing local
    file unless `--force` / `--continue`; `--delete-after-fetch` deletes the
    remote copy after a get.
  - rclone: options anywhere (cobra); an unknown option before the command
    eats it; sync deletes destination files the source lacks; `-n` /
    `--dry-run` deletes and writes nothing; `--ignore-existing` and
    `--immutable` never replace a file. The option table is rclone's own
    `help flags`, backend-only flags excluded (a value form `--x=v` of those
    is still read; `--x v` is uncovered).
  - mc: options before or after the paths; a path whose first part is not a
    configured alias is a LOCAL path. The engine cannot read mc's aliases, so
    a relative path that also exists here is ambiguous and not understood.
"""
from __future__ import annotations

import os
import re
from typing import Dict, FrozenSet, List, Optional, Tuple

from ..model import Word
from .effects import CREATE, DELETE, OVERWRITE, RUN, SEND, SERVICE_LOSS
from .infra_ops import _WORST, _before_dashdash, _label

# ---------------------------------------------------------------- shared

READ = "READ"                     # a kind for this module only: nothing changes


def _reach(w, inv, label: str, kind: Optional[str], words: List[Word], tool: str) -> None:
    """Record a remote change, or refuse to understand the line when an
    expanding word could have named an option that changes the kind."""
    if kind is None or kind == READ:
        return
    if kind not in _WORST and any(a.expands for a in _before_dashdash(words)):
        w.impact.not_understood(inv.text, f"a {tool} argument named by an expansion")
        return
    w.impact.reach(label, kind)


def _local(w, inv, state, word: Word, how: str, tool: str, whole: bool = False) -> None:
    """A local path the tool writes (OVERWRITE) or removes (DELETE). A
    directory, or `whole`, is captured whole; a missing path is created."""
    paths = w.paths([word], state, inv)
    if len(paths) != 1:
        if not paths:
            return
        w.impact.not_understood(inv.text, f"the local path {tool} writes")
        return
    p = paths[0]
    node = w.node(state, p)
    if not node.exists:
        if how != DELETE and not whole:
            w.create(state, p)
        return
    if node.is_dir or whole:
        w.within(state, p, how)
    elif how == DELETE:
        w.remove(state, p)
    else:
        w.replace(state, p, how)


def _split(words: List[Word], values: FrozenSet[str], flags: FrozenSet[str],
           abbrev: Tuple[str, ...] = ()) -> Tuple[Optional[List[Word]], Dict[str, Optional[Word]], Optional[str]]:
    """(positionals, options met -> value, the first option not known).
    `--x=v`, `--x v`, `-x v` and `-xv` for a short value option."""
    pos: List[Word] = []
    got: Dict[str, Optional[Word]] = {}
    i, done = 0, False
    while i < len(words):
        a = words[i]
        v = a.value
        if done or a.expands or not v.startswith("-") or v == "-":
            pos.append(a)
            i += 1
            continue
        if v == "--":
            done = True
            i += 1
            continue
        name, eq, glued = v.partition("=")
        if name in values:
            if eq:
                got[name] = Word(a.raw, glued, a.start, a.end, expands=a.expands)
                i += 1
            elif i + 1 < len(words):
                got[name] = words[i + 1]
                i += 2
            else:
                return None, got, name
            continue
        if name in flags:
            got[name] = None
            i += 1
            continue
        if not v.startswith("--") and len(v) > 2 and v[:2] in values:
            got[v[:2]] = Word(a.raw, v[2:], a.start, a.end, expands=a.expands)
            i += 1
            continue
        if eq:                                   # an unknown option, but its value is glued
            got[name] = Word(a.raw, glued, a.start, a.end, expands=a.expands)
            i += 1
            continue
        return None, got, name
    return pos, got, None


# ---------------------------------------------------------------- aws

_AWS_VALUES = frozenset({"endpoint-url", "output", "query", "profile", "region", "color",
                         "ca-bundle", "cli-read-timeout", "cli-connect-timeout",
                         "cli-binary-format", "cli-error-format"})
_AWS_FLAGS = frozenset({"debug", "no-verify-ssl", "no-paginate", "no-sign-request",
                        "no-cli-pager", "cli-auto-prompt", "no-cli-auto-prompt",
                        "v2-debug", "version"})
_AWS_GLOBALS = _AWS_VALUES | _AWS_FLAGS

_AWS_READ_P = frozenset({"list", "get", "describe", "search", "check", "validate", "verify",
                         "detect", "lookup", "preview", "count", "calculate", "is",
                         "estimate", "simulate", "query", "select", "scan", "download",
                         "filter", "head", "wait"})
_AWS_DELETE_P = frozenset({"delete", "terminate", "remove", "deregister", "revoke", "purge",
                           "deprovision", "abort"})
_AWS_OVERWRITE_P = frozenset({"update", "put", "modify", "set", "reset", "replace",
                              "change", "apply", "rotate", "merge", "promote", "failover",
                              "switchover", "rollback", "upgrade", "move", "transfer", "assign",
                              "associate", "disassociate", "attach", "detach", "tag", "untag",
                              "cancel", "reject", "decline", "accept", "approve", "confirm",
                              "authorize", "enable", "disable",
                              "activate", "deactivate", "release", "add", "increase",
                              "decrease", "complete", "schedule", "deploy"})
# Outside storage these mostly CREATE something new (copy-image, import-image,
# register-image, restore-db-instance-...): creations are not claimed. On a
# storage service they can replace an object (s3api copy-object).
_AWS_STORAGE_OVERWRITE_P = frozenset({"copy", "upload", "restore", "import"})
_AWS_LOSS_P = frozenset({"stop", "reboot", "pause", "suspend"})
_AWS_SEND_P = frozenset({"send", "publish", "post", "notify", "invite", "respond"})
_AWS_RUN_P = frozenset({"invoke", "execute", "submit"})

# The CLI's own local commands (not API operations), from aws v2's command
# index compared with the service models.
_AWS_LOCAL_READ = frozenset({
    ("configure", "get"), ("configure", "list"), ("configure", "export-credentials"),
    ("history", "list"), ("history", "show"), ("logs", "tail"),
    ("ecr", "get-login-password"), ("ecr-public", "get-login-password"),
    ("rds", "generate-db-auth-token"), ("dsql", "generate-db-connect-auth-token"),
    ("dsql", "generate-db-connect-admin-auth-token"), ("ddb", "select")})
_AWS_LOCAL_KIND = {("cloudformation", "deploy"): OVERWRITE, ("ecs", "deploy"): OVERWRITE,
                   ("ddb", "put"): OVERWRITE}
_AWS_UNCLAIMED_SERVICES = frozenset({"configure", "deploy", "cli-dev", "agent-toolkit"})
_AWS_UNCLAIMED = frozenset({
    ("eks", "update-kubeconfig"), ("codeartifact", "login"), ("codecommit", "credential-helper"),
    ("ec2-instance-connect", "ssh"), ("emr", "ssh"), ("emr", "socks"), ("emr", "get"),
    ("emr", "put"), ("cloudformation", "package"), ("sso", "login"), ("sso", "logout"),
    ("signin", "create-oauth2-token"), ("signin", "create-oauth2-token-with-iam")})

# Operations that write their result to a local `outfile` (aws v2 ac.index).
_AWS_OUTFILE = frozenset({
    "apigateway get-export", "apigateway get-sdk", "apigatewayv2 export-api",
    "appconfig create-hosted-configuration-version", "appconfig get-configuration",
    "appconfig get-hosted-configuration-version",
    "appconfigdata get-latest-configuration", "appsync get-introspection-schema",
    "bedrock-agentcore invoke-agent-runtime", "bedrock-runtime invoke-model",
    "cloudfront get-connection-function", "cloudfront get-function",
    "codeartifact get-package-version-asset", "codeguruprofiler get-profile",
    "datazone get-lineage-event", "ebs get-snapshot-block", "geo-maps get-glyphs",
    "geo-maps get-sprites", "geo-maps get-static-map", "geo-maps get-style-descriptor",
    "geo-maps get-tile", "glacier get-job-output", "iam create-virtual-mfa-device",
    "iot-data delete-thing-shadow", "iot-data get-thing-shadow",
    "iot-data update-thing-shadow", "iotwireless get-position-estimate",
    "iotwireless get-resource-position", "kinesis-video-archived-media get-clip",
    "kinesis-video-archived-media get-media-for-fragment-list",
    "kinesis-video-media get-media", "lakeformation get-work-unit-results",
    "lambda invoke", "lex-runtime post-content", "lex-runtime put-session",
    "lexv2-runtime put-session", "lexv2-runtime recognize-utterance",
    "location get-map-glyphs", "location get-map-sprites",
    "location get-map-style-descriptor", "location get-map-tile",
    "medialive describe-input-device-thumbnail", "mediastore-data get-object",
    "medical-imaging get-image-frame", "medical-imaging get-image-set-metadata",
    "neptune-graph execute-query", "neptunedata execute-gremlin-explain-query",
    "neptunedata execute-gremlin-profile-query",
    "neptunedata execute-open-cypher-explain-query", "omics get-read-set",
    "omics get-reference", "polly synthesize-speech", "s3api get-object",
    "s3api get-object-annotation", "s3api get-object-torrent",
    "s3api select-object-content", "sagemaker-geospatial get-tile",
    "sagemaker-runtime invoke-endpoint", "sagemakerjobruntime sample",
    "sagemakerjobruntime sample-with-response-stream",
    "schemas get-code-binding-source", "tnb get-sol-function-package-content",
    "tnb get-sol-function-package-descriptor", "tnb get-sol-network-package-content",
    "tnb get-sol-network-package-descriptor",
    "workmailmessageflow get-raw-message-content"})

_STORAGE_SERVICES = frozenset({"s3", "s3api", "s3control", "s3outposts", "s3tables",
                               "s3vectors", "glacier"})


def _aws_global(name: str) -> Optional[str]:
    """A global option's name, abbreviation allowed (argparse; VERIFIED)."""
    if name in _AWS_GLOBALS:
        return name
    hits = [g for g in _AWS_GLOBALS if g.startswith(name)]
    return hits[0] if len(hits) == 1 else None


def _aws_kind(op: str) -> Optional[str]:
    parts = op.split("-")
    if parts[0] == "batch":
        second = parts[1] if len(parts) > 1 else ""
        return READ if second == "get" else DELETE if second == "delete" else OVERWRITE
    p = parts[0]
    if p in _AWS_READ_P:
        return READ
    if p in _AWS_DELETE_P:
        return DELETE
    if p in _AWS_OVERWRITE_P:
        return OVERWRITE
    if p in _AWS_LOSS_P:
        return SERVICE_LOSS
    if p in _AWS_SEND_P:
        return SEND
    if p in _AWS_RUN_P:
        return RUN
    return None


def _aws_label(svc: str, op: str, profile: str) -> str:
    who = f"@{profile}" if profile else ""
    if svc in _STORAGE_SERVICES:
        return f"storage:aws:{svc}{who}"
    if svc == "iam":
        return f"cred:aws:iam{who}"
    if svc == "secretsmanager" or (svc == "ssm" and "parameter" in op):
        return f"secret:aws:{svc}{who}"
    if svc in ("sqs", "sns"):
        return f"queue:aws:{svc}{who}"
    return f"cloud:aws:{svc}{who}"


def aws(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    head: List[Word] = []          # service, operation (and a third word: help)
    rest: List[Word] = []          # everything after the operation that is not global
    profile = ""
    i = 0
    while i < len(args):
        a = args[i]
        v = a.value
        if v.startswith("--") and not a.expands and len(v) > 2:
            name, eq, glued = v[2:].partition("=")
            g = _aws_global(name)
            if g is not None:
                if g == "version":
                    return                                    # prints the version
                if g in _AWS_VALUES:
                    val = glued if eq else (args[i + 1].raw if i + 1 < len(args) else "")
                    if g == "profile":
                        profile = val
                    i += 1 if eq else 2
                    continue
                i += 1
                continue
            if len(head) < 2:
                w.impact.not_covered("aws (option)")          # VERIFIED: refused
                return
        if len(head) < 2:
            if a.expands:
                w.impact.not_understood(inv.text, "an aws service or operation named by an expansion")
                return
            if v.startswith("-"):
                w.impact.not_covered("aws (option)")
                return
            head.append(a)
        else:
            rest.append(a)
        i += 1
    if not head or head[0].value == "help":
        return
    svc = head[0].value
    if len(head) < 2:
        return                                                # `aws s3`: usage
    op = head[1].value
    if op == "help" or any(r.value == "help" and not r.expands for r in rest[:1]):
        return
    if any(r.value in ("--dry-run", "--generate-cli-skeleton") and not r.expands for r in rest):
        return                                                # VERIFIED: simulates or is refused
    if any(r.value.partition("=")[0] == "--user-data" for r in rest if not r.expands):
        # Rb4 (M2.3b): a script the new machine runs at boot - code shipped to
        # run elsewhere, nobody read: RUN on that service (ask).
        return _reach(w, inv, _aws_label(svc, op, profile), RUN, rest, tool)
    if svc in _AWS_UNCLAIMED_SERVICES and (svc, op) not in _AWS_LOCAL_READ:
        return w.impact.not_covered(f"aws {svc} {op}")
    if (svc, op) in _AWS_UNCLAIMED or "wizard" in op:
        return w.impact.not_covered(f"aws {svc} {op}")
    if (svc, op) in _AWS_LOCAL_READ:
        return
    if svc == "s3":
        return _aws_s3(w, inv, state, op, rest, profile)
    kind = _AWS_LOCAL_KIND.get((svc, op)) or _aws_kind(op)
    if kind is None and svc in _STORAGE_SERVICES and op.split("-")[0] in _AWS_STORAGE_OVERWRITE_P:
        kind = OVERWRITE
    if kind is None:
        return w.impact.not_covered(f"aws {svc} {op}")
    if f"{svc} {op}" in _AWS_OUTFILE:
        _aws_outfile(w, inv, state, rest, svc, op)
    _reach(w, inv, _aws_label(svc, op, profile), kind, rest, tool)


def _aws_outfile(w, inv, state, rest: List[Word], svc: str, op: str) -> None:
    """The one positional of an outfile operation is a local file it writes.
    Option values are not known by arity here, so a word right after an
    option is taken as that option's value; anything but exactly one
    remaining word is not understood."""
    cands, skip = [], False
    for a in _before_dashdash(rest):
        if skip:
            skip = False
            continue
        if a.value.startswith("--") and not a.expands:
            skip = "=" not in a.value
            continue
        cands.append(a)
    if len(cands) != 1 or cands[0].expands:
        w.impact.not_understood(inv.text, f"the local file aws {svc} {op} writes")
        return
    if cands[0].value == "-":
        return                                                # stdout
    _local(w, inv, state, cands[0], OVERWRITE, "aws")


# aws s3 transfer commands: their options (aws v1 source + aws v2 index).
_S3_VALUES = frozenset({"--acl", "--bucket-name-prefix", "--bucket-region", "--cache-control",
                        "--checksum-algorithm", "--checksum-mode", "--content-disposition",
                        "--content-encoding", "--content-language", "--content-type",
                        "--error-document", "--expected-size", "--expires", "--grants",
                        "--index-document", "--metadata", "--metadata-directive", "--page-size",
                        "--request-payer", "--source-region", "--sse-c", "--sse-c-copy-source",
                        "--sse-c-copy-source-key", "--sse-c-key", "--sse-kms-key-id",
                        "--storage-class", "--tags", "--website-redirect", "--include",
                        "--exclude", "--copy-props", "--case-conflict", "--progress-frequency",
                        "--expires-in"})
_S3_FLAGS = frozenset({"--dryrun", "--follow-symlinks", "--force", "--force-glacier-transfer",
                       "--human-readable", "--ignore-glacier-warnings", "--no-follow-symlinks",
                       "--no-guess-mime-type", "--no-progress", "--only-show-errors", "--quiet",
                       "--recursive", "--summarize", "--validate-same-s3-paths", "--delete",
                       "--exact-timestamps", "--size-only", "--no-overwrite",
                       "--progress-multiline"})
_S3_SSE = frozenset({"AES256", "aws:kms", "aws:kms:dsse"})


# Data an upload carries on its own line (metadata, headers, content fields):
# something downstream may consume it, the engine does not read it, and
# today's path does - so a CREATE carrying it is not claimed (the M2.2b1 rule
# for `kubectl create --from-literal`).
_S3_DATA = frozenset({"--metadata", "--content-disposition", "--content-encoding",
                      "--content-language", "--content-type", "--cache-control",
                      "--website-redirect", "--expires", "--grants", "--tags"})
_S3CMD_DATA = frozenset({"--add-header", "--content-disposition", "--content-type",
                         "--default-mime-type", "-m"})
_RCLONE_DATA = frozenset({"--metadata-set", "--header", "--header-upload"})


def _s3_bucket(word: Word) -> str:
    return "s3://" + word.value[5:].split("/", 1)[0]


def _aws_s3(w, inv, state, op: str, rest: List[Word], profile: str) -> None:
    # --sse takes a value only when one of its choices follows (nargs="?").
    words: List[Word] = []
    skip = False
    for i, a in enumerate(rest):
        if skip:
            skip = False
            continue
        if a.value == "--sse" and i + 1 < len(rest) and rest[i + 1].value in _S3_SSE:
            skip = True
            continue
        if a.value in ("--sse",) or a.value.startswith("--sse="):
            continue
        words.append(a)
    pos, got, bad = _split(words, _S3_VALUES, _S3_FLAGS)
    if bad is not None:
        return w.impact.not_covered("aws s3 (option)")
    who = f"@{profile}" if profile else ""
    if op in ("ls", "presign"):
        return
    if "--dryrun" in got:
        return
    # Which side a path is on decides the change: the destination always, the
    # source only for a move.
    if op in ("cp", "mv", "sync") and _side_hidden(
            pos[-1:] if op != "mv" else pos, lambda p: p.value.startswith("s3://")):
        w.impact.not_understood(inv.text, "an aws s3 path named by an expansion")
        return
    remote = [p for p in pos if p.value.startswith("s3://")]
    label = (lambda p: f"storage:aws:{_s3_bucket(p)}{who}")
    if op == "website":
        return _reach(w, inv, label(pos[0]) if pos else f"storage:aws:s3{who}", OVERWRITE, rest, "aws")
    if op == "mb":
        return w.impact.not_covered("aws s3 mb")              # a creation: not claimed
    if op in ("rb", "rm"):
        if not remote:
            return w.impact.not_covered(f"aws s3 {op}")
        return _reach(w, inv, label(remote[0]), DELETE, rest, "aws")
    if op not in ("cp", "mv", "sync"):
        return w.impact.not_covered(f"aws s3 {op}")
    if len(pos) != 2:
        w.impact.not_understood(inv.text, f"the source and destination of aws s3 {op}")
        return
    src, dst = pos
    deletes = op == "sync" and "--delete" in got
    if dst.value.startswith("s3://"):
        kind = DELETE if deletes else (CREATE if "--no-overwrite" in got else OVERWRITE)
        if kind == CREATE and _S3_DATA & set(got):
            return w.impact.not_covered(f"aws s3 {op} (data on the line)")
        _reach(w, inv, label(dst), kind, rest, "aws")
    elif dst.value != "-":
        if deletes:
            _local(w, inv, state, dst, DELETE, "aws", whole=True)
        elif "--no-overwrite" not in got:
            _local(w, inv, state, dst, OVERWRITE, "aws",
                   whole=op == "sync" or "--recursive" in got)
    if op == "mv":
        if src.value.startswith("s3://"):
            _reach(w, inv, label(src), DELETE, rest, "aws")
        elif src.value != "-":
            _local(w, inv, state, src, DELETE, "aws", whole="--recursive" in got)


# ---------------------------------------------------------------- s3cmd

_S3CMD_VALUES = frozenset({
    "--access-logging-target-prefix", "--access_key", "--access_token", "--acl-grant",
    "--acl-revoke", "--add-destination", "--add-encoding-exts", "--add-header",
    "--bucket-location", "--ca-certs", "--cache-file", "--cf-add-cname", "--cf-comment",
    "--cf-default-root-object", "--cf-remove-cname", "--config", "--content-disposition",
    "--content-type", "--default-mime-type", "--encoding", "--exclude", "--exclude-from",
    "--expiry-date", "--expiry-days", "--expiry-prefix", "--files-from", "--host",
    "--host-bucket", "--include", "--include-from", "--limit", "--limit-rate", "--max-delete",
    "--max-retries", "--multipart-chunk-size-mb", "--region", "--remove-header",
    "--restore-days", "--restore-priority", "--rexclude", "--rexclude-from", "--rinclude",
    "--rinclude-from", "--secret_key", "--server-side-encryption-kms-id", "--ssl-cert",
    "--ssl-key", "--storage-class", "--upload-id", "--ws-error", "--ws-index", "-D", "-c", "-m"})
_S3CMD_FLAGS = frozenset({
    "--acl-private", "--acl-public", "--cf-invalidate", "--cf-invalidate-default-index",
    "--cf-no-invalidate-default-index-root", "--check-certificate", "--check-hostname",
    "--check-md5", "--continue", "--continue-put", "--debug", "--delay-updates",
    "--delete-after", "--delete-after-fetch", "--delete-removed", "--disable",
    "--disable-multipart", "--dry-run", "--dump-config", "--enable", "--encrypt",
    "--follow-symlinks", "--force", "--guess-mime-type", "--human-readable-sizes", "--keep-dirs",
    "--list-allow-unordered", "--list-md5", "--long-listing", "--no-access-logging",
    "--no-check-certificate", "--no-check-hostname", "--no-check-md5", "--no-connection-pooling",
    "--no-delete-removed", "--no-encrypt", "--no-guess-mime-type", "--no-mime-magic",
    "--no-preserve", "--no-progress", "--no-reduced-redundancy", "--no-rr", "--no-ssl",
    "--preserve", "--progress", "--quiet", "--recursive", "--reduced-redundancy",
    "--requester-pays", "--rr", "--server-side-encryption", "--signature-v2",
    "--skip-destination-validation", "--skip-existing", "--ssl", "--stats", "--stop-on-error",
    "--verbatim", "--verbose", "-F", "-H", "-M", "-P", "-d", "-e", "-f", "-l", "-n", "-p", "-q",
    "-r", "-s", "-v"})
_S3CMD_READ = frozenset({"ls", "la", "du", "info", "listmp", "multipart", "sign", "gettagging",
                         "getlifecycle", "getnotification", "cflist", "cfinfo", "cfinvalinfo",
                         "ws-info"})
_S3CMD_DELETE = frozenset({"rb", "del", "rm", "abortmp", "delpolicy", "delcors", "deltagging",
                           "dellifecycle", "delnotification", "ws-delete", "cfdelete", "expire"})
_S3CMD_OVERWRITE = frozenset({"modify", "setacl", "setversioning", "setownership",
                              "setblockpublicaccess", "setobjectlegalhold",
                              "setobjectretention", "setpolicy", "setcors", "payer",
                              "fixbucket", "settagging", "setlifecycle", "setnotification",
                              "restore", "cfmodify", "cfinval"})
# VERIFIED from s3cmd's source: the commands that honour -n / --dry-run.
_S3CMD_DRY = frozenset({"del", "rm", "get", "put", "restore", "sync", "setacl", "setcors",
                        "setpolicy", "delpolicy", "delcors", "dellifecycle", "setlifecycle",
                        "payer", "fixbucket", "setobjectlegalhold", "setobjectretention"})


def s3cmd(w, inv, parsed, state, tool) -> None:
    pos, got, bad = _split(list(inv.argv[1:]), _S3CMD_VALUES, _S3CMD_FLAGS)
    if bad is not None:
        return w.impact.not_covered("s3cmd (option)")
    if "--help" in got or "-h" in got or "--version" in got or "--dump-config" in got:
        return
    if not pos:
        return
    if pos[0].expands:
        w.impact.not_understood(inv.text, "an s3cmd command named by an expansion")
        return
    cmd, ops = pos[0].value, pos[1:]
    if cmd in _S3CMD_DRY and ("-n" in got or "--dry-run" in got):
        return
    remote = [p for p in ops if p.value.startswith("s3://")]
    label = (lambda p: f"storage:s3cmd:{_s3_bucket(p)}")
    any_label = label(remote[0]) if remote else "storage:s3cmd:s3"
    if cmd in _S3CMD_READ:
        return
    if cmd in _S3CMD_DELETE:
        return _reach(w, inv, any_label, DELETE, inv.argv[1:], tool)
    if cmd in _S3CMD_OVERWRITE:
        return _reach(w, inv, any_label, OVERWRITE, inv.argv[1:], tool)
    if cmd not in ("put", "get", "cp", "mv", "sync"):
        return w.impact.not_covered(f"s3cmd {cmd}")
    moves_src = cmd == "mv" or "--delete-after-fetch" in got
    if len(ops) < 2 or _side_hidden(ops if moves_src else ops[-1:],
                                    lambda p: p.value.startswith("s3://")):
        w.impact.not_understood(inv.text, f"the paths of s3cmd {cmd}")
        return
    srcs, dst = ops[:-1], ops[-1]
    if dst.value.startswith("s3://"):
        if cmd == "sync" and "--delete-removed" in got:
            kind = DELETE
        elif "--skip-existing" in got:
            kind = CREATE
            if _S3CMD_DATA & set(got):
                return w.impact.not_covered(f"s3cmd {cmd} (data on the line)")
        else:
            kind = OVERWRITE
        _reach(w, inv, label(dst), kind, inv.argv[1:], tool)
    elif cmd == "sync" and "--delete-removed" in got:
        _local(w, inv, state, dst, DELETE, tool, whole=True)
    elif cmd == "sync" or (cmd == "get" and ("--force" in got or "-f" in got or "--continue" in got)):
        # get skips an existing local file unless --force / --continue (VERIFIED)
        _local(w, inv, state, dst, OVERWRITE, tool, whole=cmd == "sync")
    for s in srcs:
        if not s.value.startswith("s3://"):
            continue
        if cmd == "mv" or "--delete-after-fetch" in got:
            _reach(w, inv, label(s), DELETE, inv.argv[1:], tool)


# ---------------------------------------------------------------- rclone

# rclone's own `help flags`, backend-only flags excluded (rclone 1.75.1).
_RCLONE_VALUES = frozenset({
    "--backup-dir", "--bind", "--buffer-size", "--bwlimit", "--bwlimit-file",
    "--ca-cert", "--cache-dir", "--checkers", "--client-cert", "--client-key",
    "--client-pass", "--color", "--compare-dest", "--config", "--contimeout",
    "--copy-dest", "--cpuprofile", "--cutoff-mode", "--default-time", "--disable",
    "--dscp", "--dump", "--exclude", "--exclude-from", "--exclude-if-present",
    "--expect-continue-timeout", "--files-from", "--files-from-raw", "--files-from0",
    "--filter", "--filter-from", "--fs-cache-expire-duration",
    "--fs-cache-expire-interval", "--group", "--hash-filter", "--header",
    "--header-download", "--header-upload", "--http-proxy", "--include",
    "--include-from", "--kv-lock-time", "--list-cutoff", "--log-file",
    "--log-file-max-age", "--log-file-max-backups", "--log-file-max-size",
    "--log-format", "--log-level", "--low-level-retries", "--max-age", "--max-backlog",
    "--max-buffer-memory", "--max-connections", "--max-delete", "--max-delete-size",
    "--max-depth", "--max-duration", "--max-size", "--max-stats-groups",
    "--max-transfer", "--memprofile", "--metadata-exclude", "--metadata-exclude-from",
    "--metadata-filter", "--metadata-filter-from", "--metadata-include",
    "--metadata-include-from", "--metadata-mapper", "--metadata-set", "--metrics-addr",
    "--metrics-allow-origin", "--metrics-baseurl", "--metrics-cert",
    "--metrics-client-ca", "--metrics-htpasswd", "--metrics-key",
    "--metrics-max-header-bytes", "--metrics-min-tls-version", "--metrics-pass",
    "--metrics-realm", "--metrics-response-header", "--metrics-salt",
    "--metrics-server-read-timeout", "--metrics-server-write-timeout",
    "--metrics-template", "--metrics-user", "--metrics-user-from-header", "--min-age",
    "--min-size", "--modify-window", "--multi-thread-chunk-size",
    "--multi-thread-cutoff", "--multi-thread-streams",
    "--multi-thread-write-buffer-size", "--name-transform", "--order-by",
    "--partial-suffix", "--password-command", "--rc-addr", "--rc-allow-origin",
    "--rc-baseurl", "--rc-cert", "--rc-client-ca", "--rc-files", "--rc-htpasswd",
    "--rc-job-expire-duration", "--rc-job-expire-interval", "--rc-key",
    "--rc-max-header-bytes", "--rc-min-tls-version", "--rc-pass", "--rc-realm",
    "--rc-response-header", "--rc-salt", "--rc-server-read-timeout",
    "--rc-server-write-timeout", "--rc-template", "--rc-user", "--rc-user-from-header",
    "--rc-web-fetch-url", "--retries", "--retries-sleep", "--stats",
    "--stats-file-name-length", "--stats-log-level", "--stats-one-line-date-format",
    "--stats-unit", "--streaming-upload-cutoff", "--suffix", "--syslog-facility",
    "--temp-dir", "--timeout", "--tpslimit", "--tpslimit-burst",
    "--track-renames-strategy", "--transfers", "--user-agent", "-f"})
_RCLONE_FLAGS = frozenset({
    "--ask-password", "--auto-confirm", "--check-first", "--checksum",
    "--delete-after", "--delete-before", "--delete-during", "--delete-excluded",
    "--disable-http-keep-alives", "--disable-http2", "--dry-run", "--dump-bodies",
    "--dump-headers", "--error-on-no-transfer", "--fast-list", "--fix-case", "--help",
    "--human-readable", "--ignore-case", "--ignore-case-sync", "--ignore-checksum",
    "--ignore-errors", "--ignore-existing", "--ignore-size", "--ignore-times",
    "--immutable", "--inplace", "--interactive", "--links", "--log-file-compress",
    "--log-systemd", "--metadata", "--name", "--no-check-certificate",
    "--no-check-dest", "--no-console", "--no-gzip-encoding", "--no-traverse",
    "--no-unicode-normalization", "--no-update-dir-modtime", "--no-update-modtime",
    "--progress", "--progress-terminal-title", "--quiet", "--rc",
    "--rc-enable-metrics", "--rc-no-auth", "--rc-serve", "--rc-serve-no-modtime",
    "--rc-web-gui", "--rc-web-gui-force-update", "--rc-web-gui-no-open-browser",
    "--rc-web-gui-update", "--refresh-times", "--server-side-across-configs",
    "--size-only", "--stats-one-line", "--stats-one-line-date",
    "--suffix-keep-extension", "--syslog", "--track-renames", "--update",
    "--use-cookies", "--use-json-log", "--use-mmap", "--use-server-modtime",
    "--verbose", "-I", "-M", "-P", "-c", "-h", "-i", "-l", "-n", "-q", "-u", "-v"})
_RCLONE_FLAGS_ALL = _RCLONE_FLAGS | frozenset({"-L", "--copy-links", "-x", "--one-file-system",
                                                "--version"})

_RCLONE_READ = frozenset({"about", "cat", "check", "checksum", "cryptcheck", "cryptdecode",
                          "hashsum", "listremotes", "ls", "lsd", "lsf", "lsjson", "lsl",
                          "md5sum", "sha1sum", "size", "tree", "version", "help", "obscure"})
# `name:path` is a remote. On Windows a one-letter name is a drive (C:\x); on
# Linux it is a remote like any other (VERIFIED: `rclone lsf C:/x` looks up a
# remote "C").
_RCLONE_REMOTE = re.compile(r"^(?::[\w-]+[^:]*:|[\w.@+ -]+:)")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


def _rclone_remote(word: Word, windows: bool = os.name == "nt") -> bool:
    if windows and _WINDOWS_DRIVE.match(word.value):
        return False
    return bool(_RCLONE_REMOTE.match(word.value))


def _side_hidden(words: List[Word], literal) -> bool:
    """An expanding path whose literal start does not say which side it is on
    (remote or local) cannot be placed."""
    return any(p.expands and not literal(p) for p in words)


def rclone(w, inv, parsed, state, tool) -> None:
    pos, got, bad = _split(list(inv.argv[1:]), _RCLONE_VALUES, _RCLONE_FLAGS_ALL)
    if bad is not None:
        return w.impact.not_covered("rclone (option)")
    if not pos or "-h" in got or "--help" in got or "--version" in got:
        return
    if pos[0].expands:
        w.impact.not_understood(inv.text, "an rclone command named by an expansion")
        return
    cmd, ops = pos[0].value, pos[1:]
    if cmd in _RCLONE_READ:
        return
    if "-n" in got or "--dry-run" in got:
        return                                                # VERIFIED
    moves_src = cmd in ("move", "moveto", "bisync")
    if _side_hidden(ops if moves_src or len(ops) < 2 else ops[-1:], _rclone_remote):
        w.impact.not_understood(inv.text, f"the paths of rclone {cmd}")
        return
    label = (lambda p: "storage:rclone:" + p.value.split(":", 1)[0] + ":" if not p.value.startswith(":")
             else "storage:rclone:" + p.value.split(":", 2)[1])

    def lose(p: Word, how: str, whole: bool = True) -> None:
        if _rclone_remote(p):
            _reach(w, inv, label(p), how, inv.argv[1:], tool)
        else:
            _local(w, inv, state, p, how, tool, whole=whole)

    if cmd in ("delete", "purge", "cleanup", "dedupe", "rmdir", "rmdirs", "deletefile"):
        if len(ops) != 1:
            w.impact.not_understood(inv.text, f"the path of rclone {cmd}")
            return
        return lose(ops[0], DELETE, whole=cmd != "deletefile")
    if cmd in ("settier", "touch"):
        if len(ops) != 1:
            w.impact.not_understood(inv.text, f"the path of rclone {cmd}")
            return
        return lose(ops[0], OVERWRITE, whole=cmd == "settier")
    if cmd not in ("copy", "copyto", "move", "moveto", "sync", "bisync", "copyurl", "rcat"):
        return w.impact.not_covered(f"rclone {cmd}")
    if cmd == "rcat":
        if len(ops) != 1:
            w.impact.not_understood(inv.text, "the destination of rclone rcat")
            return
        return lose(ops[0], OVERWRITE, whole=False)
    if len(ops) != 2:
        w.impact.not_understood(inv.text, f"the source and destination of rclone {cmd}")
        return
    src, dst = ops
    keeps = "--ignore-existing" in got or "--immutable" in got
    if cmd in ("sync", "bisync"):
        lose(dst, DELETE)                                     # VERIFIED: extras deleted
        if cmd == "bisync":
            lose(src, DELETE)                                 # both sides are synced
    elif not keeps:
        lose(dst, OVERWRITE, whole=cmd in ("copy", "move"))
    elif _rclone_remote(dst):
        if _RCLONE_DATA & set(got):
            return w.impact.not_covered(f"rclone {cmd} (data on the line)")
        _reach(w, inv, label(dst), CREATE, inv.argv[1:], tool)
    if cmd in ("move", "moveto"):
        lose(src, DELETE, whole=cmd == "move")


# ---------------------------------------------------------------- mc

# mc's own --help (global + rm rb cp mv mirror pipe put get od undo find).
# An option that takes a value in one command and none in another is read as
# taking one: a wrong guess leaves too few paths, which is not understood.
_MC_VALUES = frozenset({
    "--action", "--attr", "--checksum", "--concurrent", "--config-dir",
    "--custom-header", "--enc-c", "--enc-kms", "--enc-s3", "--exclude",
    "--exclude-bucket", "--exclude-storageclass", "--exec", "--ignore", "--larger",
    "--last", "--legal-hold", "--limit-download", "--limit-upload", "--max-workers",
    "--maxdepth", "--metadata", "--monitoring-address", "--name", "--newer-than",
    "--older-than", "--parallel", "--part-size", "--path", "--print", "--regex",
    "--region", "--resolve", "--retention-duration", "--retention-mode", "--rewind",
    "--sc", "--smaller", "--storage-class", "--tags", "--version-id", "--vid", "-C",
    "-H", "-P", "-s"})
_MC_FLAGS = frozenset({
    "--active-active", "--autocompletion", "--bypass", "--dangerous", "--debug",
    "--disable-multipart", "--disable-pager", "--dp", "--dry-run", "--force", "--help",
    "--incomplete", "--insecure", "--json", "--no-color", "--non-current",
    "--overwrite", "--preserve", "--quiet", "--recursive", "--remove", "--retry",
    "--skip-errors", "--stdin", "--summary", "--version", "--versions", "--watch",
    "--zip", "-I", "-a", "-h", "-q", "-r", "-v", "-w"})
_MC_READ = frozenset({"ls", "cat", "head", "stat", "tree", "du", "diff", "sql", "ping", "ready",
                      "version"})
_MC_LOCAL_PREFIX = ("/", "./", "../", "~")


def _mc_side(w, state, inv, word: Word) -> Optional[bool]:
    """True: an mc alias (remote). False: a local path. None: cannot tell."""
    v = word.value
    if v.startswith(_MC_LOCAL_PREFIX) or v in (".", ".."):
        return False
    paths = w.paths([word], state, inv)
    if paths and w.node(state, paths[0]).exists:
        return None                       # a local path, unless an alias shadows it
    return True


def mc(w, inv, parsed, state, tool) -> None:
    pos, got, bad = _split(list(inv.argv[1:]), _MC_VALUES, _MC_FLAGS)
    if bad is not None:
        return w.impact.not_covered("mc (option)")
    if not pos or "--help" in got or "-h" in got or "--version" in got or "-v" in got:
        return
    if pos[0].expands:
        w.impact.not_understood(inv.text, "an mc command named by an expansion")
        return
    cmd, ops = pos[0].value, pos[1:]
    if cmd in _MC_READ:
        return
    if cmd == "find":
        if "--exec" in [a.value for a in inv.argv] or "--watch" in got:
            return w.impact.not_covered("mc find --exec")
        return
    if cmd not in ("rm", "rb", "cp", "mv", "mirror", "pipe", "put", "get", "od", "undo"):
        return w.impact.not_covered(f"mc {cmd}")
    if "--dry-run" in got and cmd in ("rm", "cp", "mv", "mirror", "undo"):
        return
    if any(p.expands for p in ops) or "--stdin" in got:
        w.impact.not_understood(inv.text, f"the paths of mc {cmd}")
        return

    def lose(p: Word, how: str, whole: bool = True) -> bool:
        side = _mc_side(w, state, inv, p)
        if side is None:
            w.impact.not_understood(inv.text, f"whether mc {cmd} {p.value} is an alias or a local path")
            return False
        if side:
            _reach(w, inv, "storage:mc:" + p.value.split("/", 1)[0], how, inv.argv[1:], tool)
        else:
            _local(w, inv, state, p, how, tool, whole=whole)
        return True

    if cmd in ("rm", "rb", "undo"):
        if not ops:
            return
        how = OVERWRITE if cmd == "undo" else DELETE
        for p in ops:
            if not lose(p, how):
                return
        return
    if cmd == "pipe":
        if len(ops) != 1:
            w.impact.not_understood(inv.text, "the destination of mc pipe")
            return
        lose(ops[0], OVERWRITE, whole=False)
        return
    if len(ops) < 2:
        w.impact.not_understood(inv.text, f"the source and destination of mc {cmd}")
        return
    srcs, dst = ops[:-1], ops[-1]
    if cmd == "mirror" and ("--remove" in got or "--overwrite" in got):
        if not lose(dst, DELETE if "--remove" in got else OVERWRITE):
            return
    elif cmd == "mirror" and "--watch" not in got:
        if not lose(dst, OVERWRITE):
            return
    elif cmd == "mirror":
        return w.impact.not_covered("mc mirror --watch")
    else:
        if not lose(dst, OVERWRITE, whole="--recursive" in got or "-r" in got):
            return
    if cmd == "mv":
        for s in srcs:
            if not lose(s, DELETE, whole="--recursive" in got or "-r" in got):
                return


# ---------------------------------------------------------------- entry

_TOOLS = {"aws": aws, "s3cmd": s3cmd, "rclone": rclone, "mc": mc}


def cloud(w, inv, parsed, state, tool) -> None:
    _TOOLS[tool](w, inv, parsed, state, tool)
