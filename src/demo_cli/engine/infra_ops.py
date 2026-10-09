"""What an infrastructure CLI does, in the engine's effect language (M2.2b1).

terraform and OpenTofu (`tofu`, the same CLI), pulumi, cdk, kubectl and helm
change things no local copy restores: cloud resources, a state backend, a
cluster. Their own options can come BEFORE the subcommand, so
`terraform -chdir=infra destroy` and `kubectl -n prod delete deploy api` walk
past a text rule anchored on `terraform destroy` or `kubectl delete`. A rule
template cannot express that; this module is the `infra` resolver.

WHAT IT CLAIMS, AND WHAT IT DOES NOT. The safety property of git_ops.py: a
subcommand, or an option before it, that this module does not list is
reported as `uncovered`, so Guard._engine_applies is False and today's text
path decides that line unchanged. Left uncovered ON PURPOSE:
  - code that runs where this engine cannot read it: kubectl exec / run /
    debug / attach / cp, helm test, terraform test (it applies for real), a
    helm --post-renderer, kustomize exec plugins - and every cdk command that
    only reads, and pulumi preview: both run the project's own program to
    find out what to do. That is M2.3's runner row, not a read;
  - a tool's own configuration and credentials (kubectl config, helm repo /
    registry / plugin, terraform and pulumi login): a kubeconfig `exec`
    credential is code that runs later, M2.2d's effect kind;
  - project files a command writes without the line naming them (pulumi
    config / new / import, cdk init / synth, helm create / package / pull,
    terraform fmt -recursive, terraform providers mirror).
  - a creation that carries on its own line something the cluster may run
    or feed to code: a command after `--` (kubectl create job / cronjob /
    deployment), values or literal data (helm install --set, kubectl create
    --from-literal), a manifest or values on stdin (`-f -`). Today's text path
    reads that text; the engine does not, so it does not claim the line.
A command whose kind DOES escalate keeps its claim even when it also runs the
project's program (cdk deploy, pulumi up): nothing that program does can make
an escalation weaker.

A REMOTE CHANGE is `reach(label, kind)`, and policy.py decides it:
  iac:<tool>[:<where>]                   -> infra_destroy
  cluster:<context>/<namespace>          -> cluster_resource_delete
  cluster-workload:<context>/<namespace> -> cluster_availability
An apply that may replace or remove resources is OVERWRITE (ruling
2026-10-06: terraform apply escalates); a destroy is DELETE; a creation is
CREATE; scale to 0 / drain / cordon is SERVICE_LOSS; scale up / uncordon /
rollout restart is SERVICE_KEEP.

EXPANSIONS. A global option's value may expand ($NS): it only names where,
and the label keeps it as written. Any other expanding word after the
subcommand could be an option (`--dry-run=client`, `--replicas=0`,
`--prune`), so it is tolerated only where the kind found is DELETE or
OVERWRITE - the two that lose the most (effects._LOSS_ORDER), which no option
can make worse; anywhere else the line is not understood.

GRAMMARS ARE VERIFIED against the releases current on 2026-10-07 - terraform
1.16.5, tofu 1.13.1, kubectl 1.37.1, helm 4.3.0, pulumi 3.268.0, cdk CLI
2.1144.0 - and, where a fact differs, the earlier major still in wide use
(helm 3.16.2; first verified 2026-10-06 with terraform 1.9.8, tofu 1.8.5,
kubectl 1.31.2, pulumi 3.137.0, cdk 2.164.1). Every option table below is
the tool's own --help, and these facts were run:
  - terraform: `-chdir` needs `=` (`-chdir infra` is an error and nothing
    runs). tofu 1.13 also takes `-chdir DIR`, and of two the LAST wins. Any
    other option before the subcommand is refused; -h, -help and --help
    anywhere before `--` print help; `--x` works like `-x`.
  - kubectl, helm, pulumi (cobra): a value option takes the next word even
    when it starts with `-` (`kubectl -n -h delete pod x` deletes in the
    namespace "-h"); a boolean option never takes a separate `true`; an
    option the tool does not know before the subcommand is refused, or eats
    the subcommand as its value. `--dry-run` takes its value only after `=`.
  - helm 4: `rollback --dry-run` became a string like install / upgrade's:
    bare or `=client` / `=server` / `=true` simulate, `=none` RUNS (helm 3's
    rollback took a boolean: `=false` runs). uninstall's stays a boolean.
  - cdk (yargs): an unknown option takes the next word as its value
    (`cdk --foo destroy` runs no command); a boolean option DOES take a
    following `true` / `false` (`cdk --trace true destroy` destroys).
"""
from __future__ import annotations

import os
from typing import Dict, FrozenSet, List, Optional, Tuple

from ..model import Word
from .effects import CREATE, DELETE, OVERWRITE, RUN, SERVICE_KEEP, SERVICE_LOSS
from .simulate import _host_path

_HELP = frozenset({"-h", "--help"})
_WORST = (DELETE, OVERWRITE)          # no option can make these lose more


class _Globals:
    """One tool's options that may stand before its subcommand."""
    __slots__ = ("values", "flags", "bool_value", "version")

    def __init__(self, values: Dict[str, str], flags: FrozenSet[str],
                 bool_value: bool = False, version: FrozenSet[str] = frozenset()):
        self.values = values            # spelling -> canonical name; takes a value
        self.flags = flags              # takes none
        self.bool_value = bool_value    # yargs: a flag takes a following true / false
        self.version = version          # prints the version: nothing runs


def _globals(w, inv, args: List[Word], g: _Globals, tool: str
             ) -> Tuple[Optional[int], Dict[str, Word], bool]:
    """(index of the subcommand, the global values met, version asked).
    Index None: no subcommand, or one that cannot be read (recorded)."""
    got: Dict[str, Word] = {}
    i = 0
    while i < len(args):
        word = args[i]
        v = word.value
        name, eq, glued = v.partition("=")
        if v.startswith("-") and name in g.values:
            if eq:
                got[g.values[name]] = Word(word.raw, glued, word.start, word.end,
                                           expands=word.expands)
                i += 1
            elif i + 1 < len(args):
                got[g.values[name]] = args[i + 1]
                i += 2
            else:
                w.impact.not_covered(f"{tool} (option)")
                return None, got, False
            continue
        if not v.startswith("--") and len(v) > 2 and v[:2] in g.values:
            got[g.values[v[:2]]] = Word(word.raw, v[2:], word.start, word.end,
                                        expands=word.expands)    # -nprod (pflag)
            i += 1
            continue
        if word.expands:
            w.impact.not_understood(inv.text, f"a {tool} option or subcommand named by an expansion")
            return None, got, False
        if v in g.version:
            return None, got, True
        if v in g.flags or (g.bool_value and v.startswith("--no-") and "--" + v[5:] in g.flags):
            i += 1
            nxt = args[i] if i < len(args) else None
            if (g.bool_value and nxt is not None and not nxt.expands
                    and nxt.value in ("true", "false")):
                i += 1
            continue
        if v.startswith("-") and v != "-":
            w.impact.not_covered(f"{tool} (option)")
            return None, got, False
        return i, got, False
    return None, got, False


def _asks_help(args: List[Word], g: _Globals, spellings: FrozenSet[str] = _HELP) -> bool:
    """A help option before `--` prints help and does nothing else - unless
    the word before it is an option that may be waiting for a value: then the
    help spelling IS that value (VERIFIED: kubectl -n -h delete pod x)."""
    prev: Optional[str] = None
    for a in args:
        if a.value == "--" and not a.expands:
            return False
        if a.value in spellings and not a.expands:
            if (prev is None or not prev.startswith("-") or "=" in prev
                    or prev in g.flags or prev in spellings):
                return True
        prev = "-?" if a.expands else a.value
    return False


def _before_dashdash(rest: List[Word]) -> List[Word]:
    out = []
    for a in rest:
        if a.value == "--" and not a.expands:
            break
        out.append(a)
    return out


def _has(rest: List[Word], *names: str) -> bool:
    return any(a.value in names and not a.expands for a in _before_dashdash(rest))


def _long(rest: List[Word], name: str, takes_next: bool = True) -> Tuple[bool, Optional[Word]]:
    """A long option after the subcommand: (present, its value). With
    takes_next False the value only comes after `=` (cobra NoOptDefVal:
    `--dry-run client` leaves `client` an operand)."""
    words = _before_dashdash(rest)
    for i, a in enumerate(words):
        if a.expands:
            continue
        if a.value == name:
            if takes_next and i + 1 < len(words):
                return True, words[i + 1]
            return True, None
        if a.value.startswith(name + "="):
            val = a.value[len(name) + 1:]
            return True, Word(a.raw, val, a.start, a.end)
    return False, None


def _action(w, inv, rest: List[Word], tool: str, g: _Globals) -> Tuple[bool, Optional[str]]:
    """The nested action of a group (`state rm`, `rollout undo`): the first
    word after the group that is not an option. A global option and its value
    are skipped; any other option there could take the next word as its
    value, so the action cannot be told and the line is uncovered. (False, _)
    when the action cannot be read (recorded)."""
    words = _before_dashdash(rest)
    i = 0
    while i < len(words):
        a = words[i]
        v = a.value
        if v.startswith("-") and v.partition("=")[0] in g.values:
            i += 1 if "=" in v else 2
            continue
        if v in g.flags:
            i += 1
            continue
        if a.expands:
            w.impact.not_understood(inv.text, f"a {tool} subcommand named by an expansion")
            return False, None
        if v.startswith("-"):
            w.impact.not_covered(f"{tool} (option)")
            return False, None
        return True, v
    return True, None


def _expands(rest: List[Word]) -> bool:
    return any(a.expands for a in _before_dashdash(rest))


def _carries_payload(rest: List[Word], data_options: Tuple[str, ...]) -> bool:
    """The line itself hands the cluster something it may RUN or feed to
    code: a command after `--`, a manifest or values on stdin (`-f -`), or
    literal data / values (`--from-literal`, `--set`). The engine reads none
    of that, and today's text path does read it, so such a line is not
    claimed (M2.2b1 review). M2.3b (Rb4): with the old path retired, such
    a line is RUN on the cluster - code shipped to run elsewhere, ask."""
    words = [a for a in rest if not a.expands]
    if any(a.value == "--" for a in words):
        return True
    for i, a in enumerate(words):
        v = a.value
        if v in ("-f", "--filename", "--values") and i + 1 < len(words) and words[i + 1].value == "-":
            return True
        if v in ("-f=-", "--filename=-", "--values=-", "-f-"):
            return True
        if any(v == o or v.startswith(o + "=") for o in data_options):
            return True
    return False


def _label(word: Optional[Word], default: str) -> str:
    if word is None:
        return default
    return word.raw if word.expands else word.value


def _remote(w, inv, label: str, kind: Optional[str], rest: List[Word], tool: str) -> None:
    """Record the change, or refuse to understand the line when an expanding
    word could have named an option that changes the kind."""
    if kind is None:
        if _expands(rest):
            w.impact.not_understood(inv.text, f"a {tool} argument named by an expansion")
        return
    if kind not in _WORST and _expands(rest):
        w.impact.not_understood(inv.text, f"a {tool} argument named by an expansion")
        return
    w.impact.reach(label, kind)


def _workdir(state, chdir: Optional[Word]) -> Optional[str]:
    """Where the tool runs: the hook's cwd, moved by a literal -chdir / --cwd.
    None when it cannot be pinned down."""
    if state.cwd is None:
        return None
    if chdir is None:
        return state.cwd
    if chdir.expands:
        return None
    p = _host_path(chdir.value)
    if p is None:
        return None
    return os.path.normpath(p if os.path.isabs(p) else os.path.join(state.cwd, p))


# ---------------------------------------------------------------- terraform / tofu

_TF_GLOBALS = _Globals(values={}, flags=frozenset(),
                       version=frozenset({"-v", "-version", "--version"}))
_TF_HELP = frozenset({"-h", "-help", "--help"})
_TF_READ = frozenset({"version", "validate", "show", "output", "graph", "console",
                      "metadata", "modules", "get"})
_FALSE = frozenset({"false", "0", "f", "F", "FALSE", "False"})   # Go strconv.ParseBool


def _go_flag(rest: List[Word], name: str) -> Optional[bool]:
    """A Go boolean flag: `-x`, `--x`, `-x=v`, `--x=v`. None when absent."""
    for a in _before_dashdash(rest):
        if a.expands:
            continue
        for spelled in ("-" + name, "--" + name):
            if a.value == spelled:
                return True
            if a.value.startswith(spelled + "="):
                return a.value[len(spelled) + 1:] not in _FALSE
    return None


def _go_value(rest: List[Word], name: str) -> Tuple[bool, Optional[Word]]:
    present, val = _long(rest, "-" + name)
    if present:
        return present, val
    return _long(rest, "--" + name)


def terraform(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    if _asks_help(args, _TF_GLOBALS, _TF_HELP):
        return
    chdir: Optional[Word] = None
    i = 0
    while i < len(args):
        word = args[i]
        v = word.value
        if v.startswith("-chdir="):
            if chdir is not None and tool != "tofu":
                w.impact.not_covered(f"{tool} (option)")     # VERIFIED: refused
                return
            chdir = Word(word.raw, v[len("-chdir="):], word.start, word.end,
                         expands=word.expands)
            i += 1
            continue
        if v == "-chdir" and tool == "tofu" and i + 1 < len(args):
            chdir = args[i + 1]                               # VERIFIED: tofu 1.13
            i += 2
            continue
        if word.expands:
            w.impact.not_understood(inv.text, f"a {tool} option or subcommand named by an expansion")
            return
        if v in _TF_GLOBALS.version:
            return
        if v.startswith("-"):
            w.impact.not_covered(f"{tool} (option)")          # VERIFIED: refused
            return
        break
    else:
        return                                                # usage only
    sub = args[i].value
    rest = args[i + 1:]
    label = f"iac:{tool}" + (f":{_label(chdir, '')}" if chdir is not None else "")
    wd = _workdir(state, chdir)

    if sub in _TF_READ:
        return
    if sub == "destroy":
        return _remote(w, inv, label, DELETE, rest, tool)
    if sub == "apply":
        return _remote(w, inv, label, DELETE if _go_flag(rest, "destroy") else OVERWRITE,
                       rest, tool)
    if sub in ("refresh", "taint", "untaint", "force-unlock"):
        return _remote(w, inv, label, OVERWRITE, rest, tool)
    if sub == "import":
        return _remote(w, inv, label, CREATE, rest, tool)
    if sub == "plan":
        if _expands(rest):
            w.impact.not_understood(inv.text, f"a {tool} plan argument named by an expansion")
            return
        present, out = _go_value(rest, "out")
        if present:
            _tf_file(w, inv, state, wd, out, tool)
        return
    if sub == "init":
        if _expands(rest):
            w.impact.not_understood(inv.text, f"a {tool} init argument named by an expansion")
            return
        if _go_flag(rest, "migrate-state") or _go_flag(rest, "force-copy"):
            w.impact.reach(label, OVERWRITE)                  # the state moves backend
        if _go_flag(rest, "upgrade"):
            _tf_lock(w, inv, state, wd)
        return
    if sub == "fmt":
        return _tf_fmt(w, inv, state, wd, rest, tool)
    if sub not in ("state", "workspace", "providers"):
        return w.impact.not_covered(f"{tool} {sub}")
    ok, action = _action(w, inv, rest, tool, _TF_GLOBALS)
    if not ok:
        return
    if sub == "state":
        if action in (None, "list", "show", "pull", "identities"):
            return
        if action == "rm":
            return _remote(w, inv, label, DELETE, rest, tool)
        if action in ("mv", "push", "replace-provider"):
            return _remote(w, inv, label, OVERWRITE, rest, tool)
        return w.impact.not_covered(f"{tool} state {action}")
    if sub == "workspace":
        if action in (None, "list", "show", "select"):
            return
        if action == "new":
            return _remote(w, inv, label, CREATE, rest, tool)
        if action == "delete":
            return _remote(w, inv, label, DELETE, rest, tool)
        return w.impact.not_covered(f"{tool} workspace {action}")
    if sub == "providers":
        if action in (None, "schema"):
            return
        if action == "lock":
            return _tf_lock(w, inv, state, wd)
        return w.impact.not_covered(f"{tool} providers {action}")
    w.impact.not_covered(f"{tool} {sub}")


def _tf_file(w, inv, state, wd: Optional[str], word: Optional[Word], tool: str) -> None:
    """`plan -out=FILE` writes FILE, relative to where terraform runs."""
    if word is None or wd is None:
        w.impact.not_understood(inv.text, f"where {tool} plan -out writes")
        return
    p = _host_path(word.value)
    if p is None:
        w.impact.not_understood(inv.text, f"where {tool} plan -out writes")
        return
    path = os.path.normpath(p if os.path.isabs(p) else os.path.join(wd, p))
    if w.node(state, path).exists:
        w.replace(state, path, OVERWRITE)
    else:
        w.create(state, path)


def _tf_lock(w, inv, state, wd: Optional[str]) -> None:
    """`init -upgrade` and `providers lock` rewrite .terraform.lock.hcl."""
    if wd is None:
        w.impact.not_understood(inv.text, "the directory terraform runs in")
        return
    w.edit(state, os.path.join(wd, ".terraform.lock.hcl"))


def _tf_fmt(w, inv, state, wd: Optional[str], rest: List[Word], tool: str) -> None:
    """fmt rewrites the .tf / .tfvars / .tftest.hcl files of ONE directory in
    place, unless -check / -write=false; -recursive reaches files the line
    does not list."""
    if _expands(rest):
        w.impact.not_understood(inv.text, f"a {tool} fmt argument named by an expansion")
        return
    if _go_flag(rest, "check") or _go_flag(rest, "write") is False:
        return
    if _go_flag(rest, "recursive"):
        w.impact.not_understood(inv.text, f"{tool} fmt -recursive rewrites files the line does not list")
        return
    ops = [a for a in rest if not a.value.startswith("-")]
    if ops and ops[0].value == "-":
        return                                                # stdin to stdout
    if wd is None:
        w.impact.not_understood(inv.text, f"the directory {tool} fmt runs in")
        return
    target = wd
    if ops:
        p = _host_path(ops[0].value)
        if p is None:
            w.impact.not_understood(inv.text, f"the path {tool} fmt rewrites")
            return
        target = os.path.normpath(p if os.path.isabs(p) else os.path.join(wd, p))
    node = w.node(state, target)
    if not node.exists:
        return
    if not node.is_dir:
        return w.edit(state, target)
    for pattern in ("*.tf", "*.tfvars", "*.tftest.hcl"):
        for hit in w.glob(state, os.path.join(target, pattern)):
            w.edit(state, hit)


# ---------------------------------------------------------------- kubectl

_KUBECTL_GLOBALS = _Globals(
    values={"--as": "as", "--as-group": "as_group", "--as-uid": "as_uid",
            "--as-user-extra": "as_user_extra", "--kuberc": "kuberc",
            "--proxy-url": "proxy_url",
            "--cache-dir": "cache_dir", "--certificate-authority": "ca",
            "--client-certificate": "cert", "--client-key": "key",
            "--cluster": "cluster", "--context": "context",
            "--kubeconfig": "kubeconfig", "--log-flush-frequency": "log_flush",
            "-n": "namespace", "--namespace": "namespace", "--password": "password",
            "--profile": "profile", "--profile-output": "profile_output",
            "--request-timeout": "timeout", "-s": "server", "--server": "server",
            "--tls-server-name": "tls_server_name", "--token": "token",
            "--user": "user", "--username": "username", "-v": "v", "--v": "v",
            "--vmodule": "vmodule"},
    flags=frozenset({"--disable-compression", "--insecure-skip-tls-verify",
                     "--match-server-version", "--warnings-as-errors"}))

_KUBECTL_READ = frozenset({"explain", "get", "describe", "logs", "top", "api-resources",
                           "api-versions", "version", "events", "diff", "wait",
                           "completion", "options", "help", "port-forward", "proxy"})
_KUBECTL_DRY = frozenset({"create", "expose", "autoscale", "delete", "apply", "replace",
                          "patch", "set", "label", "annotate", "scale", "drain",
                          "cordon", "uncordon", "taint"})


def _dry_run(rest: List[Word], real: FrozenSet[str]) -> bool:
    """`--dry-run` alone, or with a value other than one that means a real
    run. VERIFIED: the value comes only after `=`."""
    present, val = _long(rest, "--dry-run", takes_next=False)
    if not present:
        return False
    return val is None or val.value not in real


def _ns_label(prefix: str, got: Dict[str, Word], rest: List[Word], ctx_key: str) -> str:
    ns = got.get("namespace")
    if ns is None:
        present, val = _long(rest, "--namespace")
        if not present:
            present, val = _long(rest, "-n")
        ns = val if present else None
    ns_text = "*" if _has(rest, "-A", "--all-namespaces") else _label(ns, "default")
    return f"{prefix}{_label(got.get(ctx_key), 'current')}/{ns_text}"


def kubectl(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    if _asks_help(args, _KUBECTL_GLOBALS):
        return
    idx, got, _ = _globals(w, inv, args, _KUBECTL_GLOBALS, tool)
    if idx is None:
        return
    word = args[idx]
    sub = word.value
    rest = args[idx + 1:]
    objects = _ns_label("cluster:", got, rest, "context")
    workload = _ns_label("cluster-workload:", got, rest, "context")

    if sub in _KUBECTL_DRY and _dry_run(rest, frozenset({"none"})):
        return
    if sub in _KUBECTL_READ:
        return
    if sub == "kustomize":
        if _has(rest, "--enable-exec", "--enable-alpha-plugins") or _expands(rest):
            return w.impact.not_covered("kubectl kustomize (plugins)")
        return
    if sub in ("create", "replace") and _long(rest, "--raw")[0]:
        # A raw POST / PUT to any API path (a pod eviction is a POST).
        return _remote(w, inv, objects, OVERWRITE, rest, tool)
    if sub == "create" and _carries_payload(rest, ("--from-literal",)):
        # Rb4 (M2.3b): a command, a manifest or data the cluster runs or
        # consumes, nobody read: RUN on the cluster (ask), like docker run.
        return _remote(w, inv, objects, RUN, rest, tool)
    if sub in ("create", "expose", "autoscale"):
        return _remote(w, inv, objects, CREATE, rest, tool)
    if sub == "delete":
        return _remote(w, inv, objects, DELETE, rest, tool)
    if sub == "replace":
        return _remote(w, inv, objects, DELETE if _has(rest, "--force") else OVERWRITE,
                       rest, tool)
    if sub in ("label", "annotate") and _has(rest, "--list"):
        return
    if sub in ("patch", "edit", "set", "label", "annotate"):
        return _remote(w, inv, objects, OVERWRITE, rest, tool)
    if sub == "scale":
        present, val = _long(rest, "--replicas")
        if not present or val is None or val.expands or not val.value.isdigit():
            w.impact.not_understood(inv.text, "the replica count kubectl scale sets")
            return
        kind = SERVICE_LOSS if int(val.value) == 0 else SERVICE_KEEP
        return _remote(w, inv, workload, kind, rest, tool)
    if sub in ("drain", "cordon", "taint"):
        return _remote(w, inv, workload, SERVICE_LOSS, rest, tool)
    if sub == "uncordon":
        return _remote(w, inv, workload, SERVICE_KEEP, rest, tool)
    if sub == "apply":
        # Its own subcommands only as the very next word: `apply -f
        # view-last-applied` applies a file of that name.
        action = rest[0].value if rest and not rest[0].expands else None
        if action == "view-last-applied":
            return
        if action in ("set-last-applied", "edit-last-applied"):
            return _remote(w, inv, objects, OVERWRITE, rest, tool)
        # --prune deletes what the manifests no longer list.
        return _remote(w, inv, objects, DELETE if _has(rest, "--prune") else OVERWRITE,
                       rest, tool)
    if sub in ("exec", "run", "debug", "attach"):
        # M2.3b (Rb4, F2): code that runs in the cluster, nobody read it -
        # RUN there (ask), like docker exec / run.
        return _remote(w, inv, workload, RUN, rest, tool)
    if sub not in ("rollout", "cluster-info", "auth", "config", "plugin"):
        return w.impact.not_covered(f"kubectl {sub}")
    ok, action = _action(w, inv, rest, tool, _KUBECTL_GLOBALS)
    if not ok:
        return
    if sub == "rollout":
        if action in ("status", "history"):
            return
        if action in ("restart", "resume"):
            return _remote(w, inv, workload, SERVICE_KEEP, rest, tool)
        if action in ("undo", "pause"):
            return _remote(w, inv, objects, OVERWRITE, rest, tool)
        return w.impact.not_covered(f"kubectl rollout {action}")
    if sub == "cluster-info":
        if action is None:
            return
        return w.impact.not_covered(f"kubectl cluster-info {action}")
    if sub == "auth":
        if action in ("can-i", "whoami"):
            return
        if action == "reconcile":
            return _remote(w, inv, objects, OVERWRITE, rest, tool)
        return w.impact.not_covered(f"kubectl auth {action}")
    if sub == "config" and action in ("view", "get-contexts", "get-clusters",
                                      "get-users", "current-context"):
        return
    if sub == "plugin" and action == "list":
        return
    w.impact.not_covered(f"kubectl {sub}")


# ---------------------------------------------------------------- helm

_HELM_GLOBALS = _Globals(
    values={"--burst-limit": "burst", "--kube-apiserver": "apiserver",
            "--kube-as-group": "as_group", "--kube-as-user": "as_user",
            "--kube-ca-file": "ca", "--kube-context": "context",
            "--kube-tls-server-name": "tls_server_name", "--kube-token": "token",
            "--kubeconfig": "kubeconfig", "-n": "namespace", "--namespace": "namespace",
            "--qps": "qps", "--registry-config": "registry_config",
            "--repository-cache": "repository_cache",
            "--repository-config": "repository_config",
            # helm 4
            "--color": "color", "--colour": "color", "--content-cache": "content_cache"},
    flags=frozenset({"--debug", "--kube-insecure-skip-tls-verify"}))

_HELM_READ = frozenset({"completion", "env", "get", "help", "history", "hist", "lint",
                        "list", "ls", "search", "show", "inspect", "status", "verify",
                        "version"})
_HELM_UNINSTALL = frozenset({"uninstall", "del", "delete", "un"})
_HELM_DRY = frozenset({"client", "server", "true"})


def helm(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    if _asks_help(args, _HELM_GLOBALS):
        return
    idx, got, _ = _globals(w, inv, args, _HELM_GLOBALS, tool)
    if idx is None:
        return
    sub = args[idx].value
    rest = args[idx + 1:]
    label = _ns_label("cluster:", got, rest, "context")

    if sub in _HELM_READ:
        return
    if sub in ("install", "upgrade", "template") and _long(rest, "--post-renderer")[0]:
        return w.impact.not_covered(f"helm {sub} --post-renderer")   # runs a local program
    if sub == "template":
        if _expands(rest):
            w.impact.not_understood(inv.text, "a helm template argument named by an expansion")
        return
    if sub in ("install", "upgrade"):
        present, val = _long(rest, "--dry-run", takes_next=False)
        if present and (val is None or val.value in _HELM_DRY):
            return
        if sub == "install" and not _has(rest, "--replace"):
            if _carries_payload(rest, ("--set", "--set-string", "--set-file",
                                       "--set-json", "--set-literal")):
                return _remote(w, inv, label, RUN, rest, tool)        # Rb4: values the chart runs
            return _remote(w, inv, label, CREATE, rest, tool)
        return _remote(w, inv, label, OVERWRITE, rest, tool)
    if sub == "rollback":
        # helm 4: a string like install's (`=none` RUNS); helm 3: a boolean
        # (`=false` runs). Only the values that simulate in either count.
        present, val = _long(rest, "--dry-run", takes_next=False)
        if present and (val is None or val.value in _HELM_DRY):
            return
        return _remote(w, inv, label, OVERWRITE, rest, tool)
    if sub in _HELM_UNINSTALL:
        if _go_dry(rest):
            return
        return _remote(w, inv, label, DELETE, rest, tool)
    if sub not in ("dependency", "dep", "dependencies", "plugin", "repo"):
        return w.impact.not_covered(f"helm {sub}")
    ok, action = _action(w, inv, rest, tool, _HELM_GLOBALS)
    if not ok:
        return
    if sub in ("dependency", "dep", "dependencies", "plugin", "repo") and action in ("list", "ls"):
        return
    w.impact.not_covered(f"helm {sub}")


def _go_dry(rest: List[Word]) -> bool:
    """A boolean `--dry-run` (helm uninstall, in helm 3 and 4)."""
    for a in _before_dashdash(rest):
        if a.expands:
            continue
        if a.value == "--dry-run":
            return True
        if a.value.startswith("--dry-run="):
            return a.value[len("--dry-run="):] not in _FALSE
    return False


# ---------------------------------------------------------------- pulumi

_PULUMI_GLOBALS = _Globals(
    values={"--color": "color", "-C": "cwd", "--cwd": "cwd",
            "--memprofilerate": "memprofilerate", "--profiling": "profiling",
            "--tracing": "tracing", "-v": "verbose", "--verbose": "verbose",
            "--otel-traces": "otel_traces",
            # a subcommand's own option, which cobra also reads before it
            # (VERIFIED: pulumi -s dev destroy)
            "-s": "stack", "--stack": "stack"},
    flags=frozenset({"--disable-integrity-checking", "-e", "--emoji", "-Q",
                     "--fully-qualify-stack-names", "--logflow", "--logtostderr",
                     "--non-interactive"}),
    version=frozenset({"--version"}))

_PULUMI_READ = frozenset({"whoami", "version", "about", "logs", "console",
                          "gen-completion", "help"})


def pulumi(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    if _asks_help(args, _PULUMI_GLOBALS):
        return
    idx, got, _ = _globals(w, inv, args, _PULUMI_GLOBALS, tool)
    if idx is None:
        return
    sub = args[idx].value
    rest = args[idx + 1:]
    stack = got.get("stack")
    if stack is None:
        present, val = _long(rest, "--stack")
        if not present:
            present, val = _long(rest, "-s")
        stack = val if present else None
    label = "iac:pulumi" + (f":{_label(stack, '')}" if stack is not None else "")
    preview = _has(rest, "--preview-only")

    if sub in _PULUMI_READ:
        return
    if sub in ("destroy", "down", "dn"):
        return None if preview else _remote(w, inv, label, DELETE, rest, tool)
    if sub in ("up", "update", "watch"):
        return _remote(w, inv, label, OVERWRITE, rest, tool)
    if sub in ("refresh", "cancel"):
        return None if preview else _remote(w, inv, label, OVERWRITE, rest, tool)
    if sub not in ("stack", "state"):
        return w.impact.not_covered(f"pulumi {sub}")
    ok, action = _action(w, inv, rest, tool, _PULUMI_GLOBALS)
    if not ok:
        return
    if sub == "stack":
        if action in (None, "ls", "list", "output", "history", "export", "select",
                      "unselect", "get"):
            return
        if action == "init":
            return _remote(w, inv, label, CREATE, rest, tool)
        if action in ("rm", "remove", "delete"):                # VERIFIED aliases
            return _remote(w, inv, label, DELETE, rest, tool)
        if action in ("import", "rename", "tag", "change-secrets-provider"):
            return _remote(w, inv, label, OVERWRITE, rest, tool)
        return w.impact.not_covered(f"pulumi stack {action}")
    if sub == "state":
        if action == "get":
            return
        if action in ("delete", "remove", "rm"):                # VERIFIED aliases
            return _remote(w, inv, label, DELETE, rest, tool)
        if action in ("move", "rename", "repair", "unprotect", "upgrade", "protect",
                      "promote", "taint", "untaint"):
            return _remote(w, inv, label, OVERWRITE, rest, tool)
        return w.impact.not_covered(f"pulumi state {action}")
    w.impact.not_covered(f"pulumi {sub}")


# ---------------------------------------------------------------- cdk

_CDK_GLOBALS = _Globals(
    values={"-a": "app", "--app": "app", "--build": "build", "-c": "context",
            "--context": "context", "-p": "plugin", "--plugin": "plugin",
            "--profile": "profile", "--proxy": "proxy", "--ca-bundle-path": "ca",
            "-r": "role_arn", "--role-arn": "role_arn", "-o": "output",
            "--output": "output", "--unstable": "unstable",
            # cdk CLI 2.1144
            "--region": "region", "--telemetry-file": "telemetry_file"},
    flags=frozenset({"--trace", "--strict", "--lookups", "--ignore-errors", "-j", "--json",
                     "-v", "-vv", "-vvv", "--verbose", "--debug", "-i", "--ec2creds",
                     "--version-reporting", "--path-metadata", "--asset-metadata",
                     "--staging", "--notices", "--no-color", "--ci",
                     # cdk CLI 2.1144
                     "--yes", "-y", "--debug-app", "--debug-cli", "--color"}),
    bool_value=True, version=frozenset({"--version"}))


def cdk(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    if _asks_help(args, _CDK_GLOBALS):
        return
    idx, got, _ = _globals(w, inv, args, _CDK_GLOBALS, tool)
    if idx is None:
        return
    sub = args[idx].value
    rest = args[idx + 1:]
    label = "iac:cdk"
    # Every command below synthesizes, which RUNS the project's app: claimed
    # only where the kind escalates anyway (see the module docstring).
    if sub == "destroy":
        return _remote(w, inv, label, DELETE, rest, tool)
    if sub == "gc":
        return _remote(w, inv, label, DELETE, rest, tool)   # unused assets go
    if sub in ("deploy", "watch", "rollback", "bootstrap", "import"):
        return _remote(w, inv, label, OVERWRITE, rest, tool)
    if sub in ("docs", "doc", "doctor", "notices"):
        return
    w.impact.not_covered(f"cdk {sub}")


# ---------------------------------------------------------------- entry

_TOOLS = {"terraform": terraform, "tofu": terraform, "kubectl": kubectl, "helm": helm,
          "pulumi": pulumi, "cdk": cdk}


def infra(w, inv, parsed, state, tool) -> None:
    _TOOLS[tool](w, inv, parsed, state, tool)
