"""What a container CLI does (M2.2b3): docker, podman, docker-compose (and
`docker compose`).

A container's writable layer, an image, a volume or a network lives in the
container engine, not in the project: no local copy restores it. Removing one
is a `reach("container:...", DELETE)` on the `container_runtime` surface, as
the old rules escalate today; a push may replace a registry tag
(`container:registry/...`, OVERWRITE, ruling R2).

CODE IN A CONTAINER (M2.2f, ruling (b)): `run`, `exec`, `container run|exec`,
`compose run|exec` run code this engine cannot read, inside the container -
RUN on `container:<engine>`, which follows container_runtime's ask row
("Runs code demo_cli cannot read, on container_runtime"). A bind mount
(`-v "$PWD":/w`) lets that code change project files too: nothing captures
them, which is exactly why a person is asked.

WHAT IT CLAIMS, AND WHAT IT DOES NOT. Anything not listed is `uncovered`,
and today's text path decides the line unchanged. Not claimed ON PURPOSE:
create, start, build, compose up / watch (they run an image's own command,
or a build whose effects stay in the image), lifecycle commands that lose nothing persistent (stop,
kill, pause, restart, unpause: ruling R5 leaves them to today's path, which
allows them), and the tools' own configuration (login, logout, context
changes).

`cp` (M2.2d, ruling D5): into a container = OVERWRITE on the container
(`container:<engine>`, ask); out of a container = a local write, captured
like any other. VERIFIED with the docker CLI 29.8.2 and no engine reachable:
a word that starts with `.` or `/` is a local path, `NAME:PATH` names a
container, `-` is a tar stream on stdin / stdout, and a copy between two
containers is refused.

RULING R5 (2026-10-07): `compose down` removes the service containers - their
writable layers - exactly as `docker rm` does, so it escalates like it, with
or without -v / --rmi.

VERIFIED (2026-10-07) from the tools' own --help, with DOCKER_HOST pointed
at an unreachable local address so nothing reached a container engine:
docker CLI 29.8.2 (global options, commands, aliases: rm = container rm =
container remove, rmi = image rm), compose 5.6.0 (global options; down -v /
--volumes / --rmi; --dry-run), podman-remote 6.1.3 (global options). The
option parser is cobra: an option the tool does not know before the command
is refused (uncovered here).
"""
from __future__ import annotations

from typing import Dict, FrozenSet, List, Optional, Tuple

from ..model import Word
from .cloud_ops import READ, _reach
from .effects import DELETE, OVERWRITE, RUN

_DOCKER_VALUES = frozenset({"--config", "-c", "--context", "-H", "--host", "-l", "--log-level",
                            "--tlscacert", "--tlscert", "--tlskey"})
_DOCKER_FLAGS = frozenset({"-D", "--debug", "--tls", "--tlsverify"})
_PODMAN_VALUES = frozenset({"--config", "-c", "--connection", "--identity", "--log-level", "--out",
                            "--ssh", "--storage-opt", "--tls-ca", "--tls-cert", "--tls-details",
                            "--tls-key", "--url"})
_PODMAN_FLAGS: FrozenSet[str] = frozenset()
_COMPOSE_VALUES = frozenset({"--ansi", "--env-file", "-f", "--file", "--parallel", "--profile",
                             "--progress", "--project-directory", "-p", "--project-name"})
_COMPOSE_FLAGS = frozenset({"--all-resources", "--compatibility", "--dry-run"})

_READ_ACTIONS = frozenset({"ls", "list", "ps", "inspect", "logs", "stats", "top", "port", "diff",
                           "wait", "history", "df", "info", "events", "show", "du", "version"})
_DELETE_ACTIONS = frozenset({"rm", "remove", "prune"})
_GROUPS = frozenset({"container", "image", "volume", "network", "system", "builder", "buildx",
                     "plugin", "secret", "config", "node", "service", "stack", "manifest", "pod",
                     "machine", "context", "swarm", "trust", "checkpoint"})
# Groups whose rm only touches the tool's own configuration on this machine.
_LOCAL_CONFIG_GROUPS = frozenset({"context", "trust"})
_TOP_READ = frozenset({"ps", "images", "inspect", "logs", "stats", "top", "port", "diff", "events",
                       "history", "info", "version", "search", "help"})
_COMPOSE_READ = frozenset({"ps", "ls", "logs", "config", "images", "top", "version", "events",
                           "port", "stats", "help"})


def _globals(args: List[Word], values: FrozenSet[str], flags: FrozenSet[str]
             ) -> Tuple[Optional[int], Dict[str, Optional[Word]], bool]:
    """(index of the command, globals met, refused). Cobra: options before
    the command must be known to the tool."""
    got: Dict[str, Optional[Word]] = {}
    i = 0
    while i < len(args):
        a = args[i]
        v = a.value
        if a.expands:
            return i, got, False
        if not v.startswith("-") or v == "-":
            return i, got, False
        name, eq, glued = v.partition("=")
        if name in values:
            got[name] = Word(a.raw, glued, a.start, a.end) if eq else (args[i + 1] if i + 1 < len(args) else None)
            i += 1 if eq else 2
            continue
        if name in flags:
            got[name] = None
            i += 1
            continue
        if v in ("-h", "--help", "-v", "--version"):
            got[v] = None
            i += 1
            continue
        return None, got, True
    return None, got, False


def _where(tool: str, got: Dict[str, Optional[Word]]) -> str:
    for k in ("--context", "-c", "-H", "--host", "--connection", "--url"):
        w = got.get(k)
        if w is not None:
            return f"{tool}@{w.raw}"
    return f"{tool}@local"


def _help(args: List[Word]) -> bool:
    return any(a.value in ("-h", "--help") and not a.expands for a in args)


def _compose(w, inv, args: List[Word], tool: str, where: str) -> None:
    idx, got, refused = _globals(args, _COMPOSE_VALUES, _COMPOSE_FLAGS)
    if refused:
        return w.impact.not_covered("compose (option)")
    if idx is None or _help(args) or "--version" in got or "-v" in got:
        return
    sub = args[idx]
    if sub.expands:
        w.impact.not_understood(inv.text, "a compose command named by an expansion")
        return
    rest = args[idx + 1:]
    if "--dry-run" in got or any(a.value == "--dry-run" and not a.expands for a in rest):
        return
    s = sub.value
    if s in _COMPOSE_READ:
        return
    if s in ("down", "rm"):
        return _reach(w, inv, f"container:{where}", DELETE, rest, tool)    # ruling R5
    if s == "push":
        return _reach(w, inv, f"container:registry/{where}", OVERWRITE, rest, tool)
    if s in ("run", "exec"):
        return w.impact.reach(f"container:{where}", RUN)          # M2.2f, ruling (b)
    w.impact.not_covered(f"compose {s}")


_CP_FLAGS = frozenset({"-a", "--archive", "-L", "--follow-link", "-q", "--quiet"})


def _cp_side(v: str) -> bool:
    """Does this `docker cp` operand name a container (NAME:PATH)?"""
    if v.startswith((".", "/")) or ":" not in v:
        return False
    return not (len(v) > 1 and v[1] == ":" and v[0].isalpha())   # C:\x on Windows


def _cp(w, inv, state, rest: List[Word], tool: str, where: str) -> None:
    ops = []
    for a in rest:
        if a.expands:
            w.impact.not_understood(inv.text, f"a {tool} cp operand named by an expansion")
            return
        if a.value.startswith("-") and a.value != "-":
            if a.value not in _CP_FLAGS:
                return w.impact.not_covered(f"{tool} cp (option)")
            continue
        ops.append(a)
    if len(ops) != 2:
        return
    src, dst = ops
    if _cp_side(dst.value) and not _cp_side(src.value):
        return _reach(w, inv, f"container:{where}", OVERWRITE, [], tool)
    if _cp_side(src.value) and not _cp_side(dst.value):
        if dst.value == "-":
            return                                            # a tar stream to stdout
        for p in w.paths([dst], state, inv):
            n = w.node(state, p)
            if n.exists and n.is_dir:
                w.within(state, p, OVERWRITE)                 # copied INTO it: captured whole
            elif n.exists:
                w.replace(state, p, OVERWRITE)
            else:
                w.create(state, p)
        return
    # both local, or both containers: docker refuses


def container(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    if tool == "docker-compose":
        return _compose(w, inv, args, tool, "docker-compose@local")
    values, flags = (_PODMAN_VALUES, _PODMAN_FLAGS) if tool == "podman" else (_DOCKER_VALUES, _DOCKER_FLAGS)
    idx, got, refused = _globals(args, values, flags)
    if refused:
        return w.impact.not_covered(f"{tool} (option)")
    if idx is None:
        return                                                  # help / version / usage
    if "-v" in got or "--version" in got or "-h" in got or "--help" in got:
        return
    cmd = args[idx]
    if cmd.expands:
        w.impact.not_understood(inv.text, f"a {tool} command named by an expansion")
        return
    rest = args[idx + 1:]
    where = _where(tool, got)
    c = cmd.value
    if c == "compose":
        return _compose(w, inv, rest, f"{tool} compose", where)
    if _help(rest):
        return
    if c in _TOP_READ:
        return
    if c in ("rm", "rmi"):
        return _reach(w, inv, f"container:{where}", DELETE, rest, tool)
    if c in ("run", "exec") or (c == "container" and rest and not rest[0].expands
                                and rest[0].value in ("run", "exec")):
        return w.impact.reach(f"container:{where}", RUN)          # M2.2f, ruling (b)
    if c == "cp" or (c == "container" and rest and rest[0].value == "cp"):
        return _cp(w, inv, state, rest[1:] if c == "container" else rest, tool, where)
    if c == "push":
        img = next((a.raw for a in rest if not a.value.startswith("-")), "?")
        return _reach(w, inv, f"container:registry/{img}", OVERWRITE, rest, tool)
    if c not in _GROUPS:
        return w.impact.not_covered(f"{tool} {c}")
    # The action is the word right after the group; an option there could
    # take the next word as its value, so the action is not guessed.
    act = rest[0] if rest else None
    if act is None:
        return
    if act.value.startswith("-") and not act.expands:
        return w.impact.not_covered(f"{tool} {c} (option)")
    if act.expands:
        w.impact.not_understood(inv.text, f"a {tool} {c} action named by an expansion")
        return
    a = act.value
    if a in _READ_ACTIONS:
        return
    if c == "system" and a == "reset":
        return _reach(w, inv, f"container:{where}", DELETE, rest, tool)    # podman: everything
    if a in _DELETE_ACTIONS and c not in _LOCAL_CONFIG_GROUPS:
        return _reach(w, inv, f"container:{where}", DELETE, rest, tool)
    if c == "image" and a == "push":
        img = next((x.raw for x in rest[1:] if not x.value.startswith("-")), "?")
        return _reach(w, inv, f"container:registry/{img}", OVERWRITE, rest, tool)
    if c == "stack" and a == "down":
        return _reach(w, inv, f"container:{where}", DELETE, rest, tool)
    w.impact.not_covered(f"{tool} {c} {a}")
