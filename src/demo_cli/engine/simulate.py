"""Play a command line's effects in order, over a virtual filesystem.

The real filesystem is only READ (lstat, listdir, glob): nothing is written,
nothing is executed, no subprocess starts. Effects land in an overlay.

CONTENT ORIGIN. Every overlay node remembers whose content it holds: the
pre-existing path it came from, or NEW (made by this command). Destroying a
node records its pre-existing origins, so what `destroys` lists is data that
existed before the command - in `mv a b && rm b`, the loss at b is a's.
CREATE applies only where nothing exists: `touch x && rm x` destroys x when
x was already there, and nothing when it was not.

SEPARATORS, as sets of possible states (merges union what may exist and
where content may come from, so they can only add to what is destroyed):
  a && b   b runs in the state after a succeeded
  a || b   b runs in the state after a failed: before a, or part-way
  a ; b    b runs after a either way
  a | b    each side in its own subshell; files are shared, cwd/vars are not
A command that fails may have done part of its work, so its failure state is
the merge of before and after - except cd, which either moves or does not,
and does not when the directory is missing. cd into a directory that exists
is taken to succeed, as target resolution does today.

SUBSHELLS: $( ), -c payloads, heredocs fed to a shell, pipeline members and
( ... ) groups run with a copy of cwd and variables; their file effects stay.
"""
from __future__ import annotations

import contextlib
import fnmatch
import glob as _glob
import os
import re
import stat
import time
from typing import Dict, FrozenSet, List, Optional, Tuple

# B0.1 (msg 037), measured 2026-10-04: Linux process_time tick 0.0009 ms;
# Windows process_time tick 15.625 ms -> perf_counter.
_CPU_CLOCK = "perf_counter" if os.name == "nt" else "process_time"
WALL_CEILING_MS = 250.0

from ..model import Script, parse
from .effects import CREATE, DELETE, MKDIR, OVERWRITE, TRUNCATE, Impact
from .invocation import Invocation, build, parse_options, reads_stdin_script
from .rules import (LAZY_FAMILIES, READ_ONLY, RULES, SHELLS, Rule, applies, family_rules,
                    rules_by_tool)
from .words import Unknown, expand

NEW = ""                     # the origin of content this command itself makes
SINKS = frozenset({"/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr", "/dev/tty",
                   "/dev/full", "/dev/random", "/dev/urandom", "/dev/stdin"})
MAX_GLOB = 10_000
MAX_DEPTH = 8
_WRITES = (">", ">|", "&>", ">&", ">>", "&>>")
_VAR_BUILTINS = ("export", "readonly", "declare", "typeset", "local")
_DRIVE = re.compile(r"^/([A-Za-z])(/.*)?$")


def _host_path(f: str, windows: bool = os.name == "nt") -> Optional[str]:
    """A shell word as a path on this host. Git Bash on Windows: /c/x -> C:\\x.
    Any other absolute POSIX path on Windows (/tmp, /usr, /home) maps to an
    MSYS root we cannot know: None, and the caller records it as unknown."""
    if not windows:
        return f
    m = _DRIVE.match(f)
    if m:
        rest = (m.group(2) or "").lstrip("/").replace("/", "\\")
        return f"{m.group(1).upper()}:\\{rest}"
    if f.startswith("/"):
        return None
    return f


class BudgetExceeded(Exception):
    pass


class Budget:
    def __init__(self, ms: float):
        clock = getattr(time, _CPU_CLOCK)
        self.deadline = clock() + ms / 1000.0
        wall_now = time.perf_counter()
        # Bound wall time by ceiling, but don't truncate huge test budgets
        self.wall_deadline = wall_now + max(WALL_CEILING_MS, ms) / 1000.0

    def check(self) -> None:
        clock = getattr(time, _CPU_CLOCK)
        if clock() > self.deadline or time.perf_counter() > self.wall_deadline:
            raise BudgetExceeded()

    @contextlib.contextmanager
    def paused(self):
        """Pause both deadlines while untimed work (imports, zip directory reads) runs."""
        c0 = getattr(time, _CPU_CLOCK)()
        w0 = time.perf_counter()
        try:
            yield
        finally:
            self.deadline += getattr(time, _CPU_CLOCK)() - c0
            self.wall_deadline += time.perf_counter() - w0


class Node:
    """One path's state. Treated as immutable: every change makes a new Node."""
    __slots__ = ("exists", "is_dir", "origins", "moved_from", "copy_of")

    def __init__(self, exists: bool, is_dir: bool = False,
                 origins: FrozenSet[str] = frozenset(), moved_from: Optional[str] = None,
                 copy_of: Optional[str] = None):
        self.exists = exists
        self.is_dir = is_dir
        self.origins = origins
        self.moved_from = moved_from      # a real directory whose children now live here
        self.copy_of = copy_of            # a real directory whose children were COPIED here


ABSENT = Node(False)


class State:
    __slots__ = ("nodes", "cwd", "prev", "vars")

    def __init__(self, nodes: Dict[str, Node], cwd: Optional[str], prev: Optional[str],
                 vars_: Dict[str, Optional[str]]):
        self.nodes, self.cwd, self.prev, self.vars = nodes, cwd, prev, vars_

    def copy(self) -> "State":
        return State(dict(self.nodes), self.cwd, self.prev, dict(self.vars))


class World:
    def __init__(self, rules: Tuple[Rule, ...], budget: Budget):
        self.table = rules_by_tool(rules)
        self.budget = budget
        self.real: Dict[str, Node] = {}
        self.impact = Impact()
        self.upstream: Optional[Invocation] = None     # the pipeline member feeding stdin
        self.sql_target: Tuple[Optional[str], Optional[str]] = (None, None)  # --db, --db-url

    def read_text(self, state: State, path: str, cap: int) -> Tuple[Optional[str], str]:
        """A file's text AS THE LINE LEAVES IT at this point, or (None, why)
        (C2 review, R4). Content created or overwritten earlier on the line
        is unknown; a moved file is read at its origin.

        Only a REGULAR file is read, and never more than `cap` + 1 bytes (I1a,
        msg 049): open() on a FIFO blocks until a writer comes and /dev/zero
        never ends - the budget is checked between steps and cannot stop either."""
        n = self.node(state, path)
        name = os.path.basename(path)
        if not n.exists:
            return None, f"{name} does not exist"
        if n.is_dir:
            return None, f"{name} is a directory"
        if NEW in n.origins or len(n.origins) != 1:
            return None, f"{name} is written earlier on this line"
        origin = next(iter(n.origins))
        if origin == "/dev/null":
            return "", ""                                # reads as empty, as open() did
        try:
            st = os.stat(origin)                          # follows a link, as open() does
            if not stat.S_ISREG(st.st_mode):
                return None, f"{name} is not a regular file"
            if st.st_size > cap:
                return None, f"{name} is larger than {cap // 1024} KiB"
            fd = os.open(origin, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
                         | getattr(os, "O_BINARY", 0))
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):    # replaced after the stat
                    return None, f"{name} is not a regular file"
                data = b""
                while len(data) <= cap:
                    chunk = os.read(fd, cap + 1 - len(data))
                    if not chunk:
                        break
                    data += chunk
            finally:
                os.close(fd)
            if len(data) > cap:                               # grew after the stat
                return None, f"{name} is larger than {cap // 1024} KiB"
            text = data.decode("utf-8", errors="replace")
            return text.replace("\r\n", "\n").replace("\r", "\n"), ""   # what text mode did
        except OSError as exc:
            return None, f"{name} cannot be read ({exc.strerror})"

    # ---- the filesystem, as the simulation has changed it ----------------
    def real_node(self, path: str) -> Node:
        n = self.real.get(path)
        if n is None:
            try:
                n = Node(True, stat.S_ISDIR(os.lstat(path).st_mode), frozenset({path}))
            except OSError:
                n = ABSENT
            self.real[path] = n
        return n

    def node(self, state: State, path: str) -> Node:
        n = state.nodes.get(path)
        if n is not None:
            return n
        tail: List[str] = []
        cur = path
        while True:
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            tail.insert(0, os.path.basename(cur))
            a = state.nodes.get(parent)
            if a is not None:
                if not a.exists or not a.is_dir:
                    return ABSENT                     # removed, or not a directory
                if a.moved_from:
                    return self.real_node(os.path.join(a.moved_from, *tail))
                if a.copy_of:                         # a copy: the same names, new content
                    r = self.real_node(os.path.join(a.copy_of, *tail))
                    return Node(True, r.is_dir, frozenset({NEW})) if r.exists else ABSENT
                if a.origins == frozenset({NEW}):
                    return ABSENT                     # a new directory holds only what the overlay says
                break
            cur = parent
        return self.real_node(path)

    def is_empty(self, state: State, path: str) -> bool:
        n = self.node(state, path)
        src = n.moved_from or path
        try:
            names = os.listdir(src) if NEW not in n.origins or n.moved_from else []
        except OSError:
            names = []
        if any(self.node(state, os.path.join(path, c)).exists for c in names):
            return False
        prefix = path + os.sep
        return not any(q.startswith(prefix) and m.exists and os.path.dirname(q) == path
                       for q, m in state.nodes.items())

    def glob(self, state: State, pattern: str) -> List[str]:
        hits = _glob.glob(pattern)
        if len(hits) > MAX_GLOB:
            raise Unknown("the glob matches too much to list")
        out = [os.path.normpath(h) for h in sorted(hits)
               if self.node(state, os.path.normpath(h)).exists]
        pdir, pbase = os.path.split(pattern)
        if not any(c in pdir for c in "*?["):
            for q, m in state.nodes.items():
                if (m.exists and q not in out and os.path.dirname(q) == os.path.normpath(pdir)
                        and fnmatch.fnmatchcase(os.path.basename(q), pbase)
                        and (pbase.startswith(".") or not os.path.basename(q).startswith("."))):
                    out.append(q)
        return sorted(out)

    def merge(self, a: Optional[State], b: Optional[State]) -> Optional[State]:
        if a is None:
            return b
        if b is None or a is b:
            return a
        nodes: Dict[str, Node] = {}
        for k in set(a.nodes) | set(b.nodes):
            x, y = self.node(a, k), self.node(b, k)
            nodes[k] = Node(x.exists or y.exists, x.is_dir or y.is_dir,
                            x.origins | y.origins, x.moved_from or y.moved_from,
                            x.copy_of or y.copy_of)
        vars_: Dict[str, Optional[str]] = {}
        for k in set(a.vars) | set(b.vars):
            va, vb = a.vars.get(k, "\0missing"), b.vars.get(k, "\0missing")
            vars_[k] = va if va == vb else None
        return State(nodes, a.cwd if a.cwd == b.cwd else None,
                     a.prev if a.prev == b.prev else None, vars_)

    # ---- recording --------------------------------------------------------
    def lose(self, n: Node, how: str) -> None:
        for origin in n.origins:
            if origin != NEW:
                self.impact.destroy(origin, how, self.real_node(origin).is_dir)

    def paths(self, words, state: State, inv: Invocation) -> List[str]:
        out: List[str] = []
        for w in words:
            self.budget.check()
            try:
                fields = expand(w, state.vars, state.cwd, lambda p: self.glob(state, p))
            except Unknown as u:
                self.impact.not_understood(inv.text, str(u))
                continue
            for f in fields:
                if w.expands and f.startswith("-") and f != "-":
                    # I1a (msg 049): the tool reads this value as an OPTION -
                    # `X=-rf; rm $X src` is `rm -rf src` - but parse_options
                    # filed the word as an operand before its value was known.
                    self.impact.not_understood(
                        inv.text, "an expansion that starts with '-' may be read as an option")
                    continue
                if f in SINKS or f.startswith("/dev/fd/"):
                    out.append(f)
                    continue
                hf = _host_path(f)
                if hf is None:
                    self.impact.not_understood(inv.text, "a Git Bash path that cannot be mapped to Windows")
                    continue
                f = hf
                if os.path.isabs(f):
                    out.append(os.path.normpath(f))
                elif state.cwd is None:
                    self.impact.not_understood(inv.text, "the working directory is unknown")
                else:
                    out.append(os.path.normpath(os.path.join(state.cwd, f)))
        return out

    # ---- effects ------------------------------------------------------------
    def device(self, path: str) -> bool:
        """True when `path` is a device, not a file. The sinks swallow data;
        anything else under /dev (a disk, a partition) is a surface no local
        copy restores - REMOTE, so the verdict is ESCALATE (review C1, fix 2)."""
        if not path.startswith("/dev/"):
            return False
        if path in SINKS or path.startswith("/dev/fd/"):
            return True
        self.impact.reach("device:" + path, OVERWRITE)
        return True

    def replace(self, state: State, path: str, how: str,
                backup: Optional[str] = None, is_dir: bool = False) -> None:
        """New content at an EXISTING `path`: its old content is lost. A
        backup does not change that: it is the TOOL's copy, which the next
        command can delete and demo_cli undo cannot restore (review C1). The
        backup path is written too: what was there before is lost (fix 1),
        or it is created."""
        n = self.node(state, path)
        self.lose(n, how)
        if backup:
            self.put(state, backup, Node(True, n.is_dir, n.origins, n.moved_from, n.copy_of))
        state.nodes[path] = Node(True, is_dir, frozenset({NEW}))
        self.impact.touched.add(path)

    def put(self, state: State, path: str, node: Node) -> None:
        """Write `node` at `path`, destroying what was there."""
        old = self.node(state, path)
        if old.exists:
            self.lose(old, OVERWRITE)
        else:
            self.impact.created.append(path)
        state.nodes[path] = node
        self.impact.touched.add(path)

    def write(self, state: State, path: str, appending: bool) -> None:
        if self.device(path):
            return
        n = self.node(state, path)
        if n.exists:
            if n.is_dir:
                return                                   # bash: Is a directory
            self.impact.touched.add(path)
            if appending:
                self.impact.changes.add(path)
                return
            self.lose(n, TRUNCATE)
            state.nodes[path] = Node(True, False, frozenset({NEW}))
            return
        parent = self.node(state, os.path.dirname(path))
        if parent.exists and parent.is_dir:
            state.nodes[path] = Node(True, False, frozenset({NEW}))
            self.impact.created.append(path)
            self.impact.touched.add(path)

    def edit(self, state: State, path: str, suffix: Optional[str] = None) -> None:
        """Rewrite an existing regular file in place (sed -i, perl -i, a
        formatter). An empty suffix means no backup."""
        n = self.node(state, path)
        if not n.exists or n.is_dir:
            return
        self.replace(state, path, OVERWRITE, backup=(path + suffix) if suffix else None)

    def within(self, state: State, path: str, how: str) -> None:
        """The tool may change anything under the directory `path` without the
        line naming it (find -delete, a formatter or rsync on a directory):
        the directory is recorded as destroyed - captured whole."""
        n = self.node(state, path)
        if not n.exists:
            return
        self.lose(n, how)
        prefix = path + os.sep
        for q, m in list(state.nodes.items()):
            if q.startswith(prefix) and m.exists:
                self.lose(m, how)
        self.impact.within.add(path)
        self.impact.touched.add(path)

    def mkdir(self, state: State, path: str, parents: bool) -> None:
        if self.node(state, path).exists:
            return                                       # exists: nothing (mkdir -p) or an error
        parent = os.path.dirname(path)
        pn = self.node(state, parent)
        if not pn.exists:
            if not parents or parent == path:
                return
            self.mkdir(state, parent, True)
            pn = self.node(state, parent)
        if not pn.is_dir:
            return
        state.nodes[path] = Node(True, True, frozenset({NEW}))
        self.impact.created.append(path)
        self.impact.touched.add(path)

    def delete(self, state: State, path: str, eff, flags) -> None:
        n = self.node(state, path)
        if not n.exists:
            return
        if n.is_dir:
            if eff.files_only:
                return
            recursive = bool(eff.recursive_if and eff.recursive_if in flags)
            empty_ok = eff.dirs_only or bool(eff.dir_if and eff.dir_if in flags)
            if not recursive and not (empty_ok and self.is_empty(state, path)):
                return
        elif eff.dirs_only:
            return
        self.remove(state, path)

    def remove(self, state: State, path: str) -> None:
        self.lose(self.node(state, path), DELETE)
        prefix = path + os.sep
        for q, m in list(state.nodes.items()):
            if q.startswith(prefix) and m.exists:
                self.lose(m, DELETE)                     # content moved into the tree dies with it
                state.nodes[q] = ABSENT
        state.nodes[path] = ABSENT
        self.impact.touched.add(path)

    def create(self, state: State, path: str) -> None:
        if self.node(state, path).exists:
            return                                       # touch on a file: no new content
        parent = self.node(state, os.path.dirname(path))
        if parent.exists and parent.is_dir:
            state.nodes[path] = Node(True, False, frozenset({NEW}))
            self.impact.created.append(path)
            self.impact.touched.add(path)

    def dest_pairs(self, state: State, paths: List[str], parsed, inv: Invocation,
                   single_into_cwd: bool = False) -> List[Tuple[str, str]]:
        """GNU cp / mv / ln / install destinations: -t DIR; else the last
        operand, INTO it when it is an existing directory (unless -T); with
        one operand only ln works (a link of that name in the cwd)."""
        target = parsed.options.get("target")
        if target:
            dirs = self.paths(target[-1:], state, inv)
            return [(p, os.path.join(dirs[0], os.path.basename(p.rstrip(os.sep))))
                    for p in paths] if dirs else []
        if not paths:
            return []
        if len(paths) == 1:
            if single_into_cwd and state.cwd is not None:
                return [(paths[0], os.path.join(state.cwd, os.path.basename(paths[0])))]
            return []
        dest, srcs = paths[-1], paths[:-1]
        dn = self.node(state, dest)
        into = (dn.exists and (dn.is_dir or os.path.isdir(dest))
                and "no_target_dir" not in parsed.flags)
        if into:
            return [(p, os.path.join(dest, os.path.basename(p.rstrip(os.sep)))) for p in srcs]
        if len(srcs) != 1:
            return []
        if parsed.operands and parsed.operands[-1].value.endswith("/"):
            # VERIFIED (GNU coreutils 9): `dest/` that is not a directory
            # fails for a file source; only a directory source may take the
            # name (cp -r, mv), and ln never does.
            if single_into_cwd or not self.node(state, srcs[0]).is_dir:
                return []
        return [(srcs[0], dest)]

    def backup_name(self, dst: str, parsed) -> Optional[str]:
        """The backup path for -b / --backup[=CONTROL] / -S SUFFIX, or None.
        Numbered backups (=numbered, =t) pick a fresh name, so they never
        overwrite an older backup (the file itself is still destroyed)."""
        if "backup" not in parsed.flags and "suffix" not in parsed.options:
            return None
        control = [w.value for w in parsed.options.get("backup", [])]
        if control and control[-1] in ("numbered", "t"):
            k = 1
            while self.real_node(f"{dst}.~{k}~").exists:
                k += 1
            return f"{dst}.~{k}~"
        suffix = parsed.options.get("suffix")
        return dst + (suffix[-1].value if suffix else "~")

    def copy(self, state: State, src: str, dst: str, parsed, recursive: bool) -> None:
        if self.device(dst):
            return
        sn = self.node(state, src)
        if not sn.exists or (sn.is_dir and not recursive):
            return
        dn = self.node(state, dst)
        if dn.exists:
            if "no_clobber" in parsed.flags:
                return
            if dn.is_dir:
                if sn.is_dir:
                    self.within(state, dst, OVERWRITE)   # a merge into an existing tree
                return                                   # a file cannot replace a directory
            if sn.is_dir:
                return
            self.replace(state, dst, OVERWRITE, backup=self.backup_name(dst, parsed))
            return
        parent = self.node(state, os.path.dirname(dst))
        if not (parent.exists and parent.is_dir):
            return
        copy_of = (sn.moved_from or src) if sn.is_dir and NEW not in sn.origins else None
        state.nodes[dst] = Node(True, sn.is_dir, frozenset({NEW}), None, copy_of)
        self.impact.created.append(dst)
        self.impact.touched.add(dst)

    def link(self, state: State, target: str, path: str, parsed) -> None:
        n = self.node(state, path)
        if n.exists:
            backup = self.backup_name(path, parsed)
            if "force" not in parsed.flags and not backup:
                return                                   # ln: File exists
            if n.is_dir:
                return
            self.replace(state, path, DELETE, backup=backup)
            return
        parent = self.node(state, os.path.dirname(path))
        if parent.exists and parent.is_dir:
            state.nodes[path] = Node(True, False, frozenset({NEW}))
            self.impact.created.append(path)
            self.impact.touched.add(path)

    def move(self, state: State, pairs: List[Tuple[str, str]], parsed) -> None:
        for src, dst in pairs:
            sn = self.node(state, src)
            if not sn.exists or dst == src:
                continue
            dn = self.node(state, dst)
            backup = None
            if dn.exists:
                if "no_clobber" in parsed.flags:
                    continue
                if dn.is_dir != sn.is_dir:
                    continue
                self.lose(dn, OVERWRITE)                 # a backup does not undo it
                backup = self.backup_name(dst, parsed)
                if backup:
                    self.put(state, backup, Node(True, dn.is_dir, dn.origins, dn.moved_from,
                                                 dn.copy_of))
            moved_from = sn.moved_from or (src if sn.is_dir and NEW not in sn.origins else None)
            state.nodes[dst] = Node(True, sn.is_dir, sn.origins, moved_from, sn.copy_of)
            prefix = src + os.sep
            for q, m in list(state.nodes.items()):
                if q.startswith(prefix):
                    state.nodes[dst + q[len(src):]] = m
                    state.nodes[q] = ABSENT
            state.nodes[src] = ABSENT
            self.impact.touched.update((src, dst))

    # ---- running ------------------------------------------------------------
    def run_script(self, script: Script, state: State, depth: int = 0) -> State:
        if depth > MAX_DEPTH:
            self.impact.not_understood(script.line[:80], "nested too deep to follow")
            return state
        invs = build(script)
        if not invs:
            return state
        elements: List[Tuple[str, List[Invocation]]] = []
        op, pipe = "&&", []
        for inv in invs:
            pipe.append(inv)
            if inv.sep in ("|", "|&"):
                continue
            elements.append((op, pipe))
            op, pipe = inv.sep, []
        if pipe:
            elements.append((op, pipe))

        ok: Optional[State] = state
        fail: Optional[State] = None
        saved: Dict[int, Tuple] = {}
        level = 0
        for op, pipe in elements:
            self.budget.check()
            if op not in ("&&", "||"):                   # ; & newline: a new list
                ok, fail, op = self.merge(ok, fail), None, "&&"
            src = ok if op == "&&" else fail
            if src is None:
                continue                                 # never runs on any path
            src = src.copy()
            want = pipe[0].depth
            while level < want:
                level += 1
                saved[level] = (src.cwd, src.prev, dict(src.vars))
            while level > want:
                src.cwd, src.prev, vars_ = saved.pop(level)
                src.vars = dict(vars_)
                level -= 1
            done, failed = self.run_pipeline(pipe, src, depth)
            if op == "&&":
                ok, fail = done, self.merge(fail, failed)
            else:
                ok, fail = self.merge(ok, done), failed
        final = self.merge(ok, fail) or state
        while level > 0:
            final.cwd, final.prev, vars_ = saved.pop(level)
            final.vars = dict(vars_)
            level -= 1
        return final

    def run_pipeline(self, pipe: List[Invocation], pre: State,
                     depth: int) -> Tuple[Optional[State], Optional[State]]:
        if len(pipe) == 1:
            return self.run(pipe[0], pre, depth, piped_in=False)
        state = pre
        for k, inv in enumerate(pipe):
            member = state.copy()
            member.cwd, member.prev, member.vars = pre.cwd, pre.prev, dict(pre.vars)
            done, failed = self.run(inv, member, depth, piped_in=k > 0,
                                    upstream=pipe[k - 1] if k else None)
            state = self.merge(done, failed) or member
        state.cwd, state.prev, state.vars = pre.cwd, pre.prev, dict(pre.vars)
        return state, self.merge(pre, state)

    def subshell(self, script: Script, state: State, depth: int) -> None:
        """Run `script` with a copy of cwd and variables; keep its file effects."""
        end = self.run_script(script, state.copy(), depth + 1)
        state.nodes = end.nodes

    def run(self, inv: Invocation, state: State, depth: int, piped_in: bool,
            upstream: Optional[Invocation] = None) -> Tuple[Optional[State], Optional[State]]:
        for sub in inv.subs:                             # $( ) runs before the command
            self.subshell(sub, state, depth)
        if inv.clause:
            if inv.clause in ("for", "select") and len(inv.command.words) > 1:
                state.vars[inv.command.words[1].value] = None   # loop variable (C)
            return state, None
        if not inv.argv:
            for w in inv.prefix:
                self.assign(w, state)
            self.redirect(inv, state)
            return state, None

        try:
            head = expand(inv.argv[0], state.vars, state.cwd, lambda p: [], plain=True)
        except Unknown as u:
            self.impact.not_understood(inv.text, f"the command word: {u}")
            return state, state
        tool = os.path.basename(head[0].replace("\\", "/")) if head else ""
        if tool.lower().endswith(".exe"):
            tool = tool[:-4]

        shell_stdin = False
        if tool in SHELLS and inv.payload is None:
            shell_stdin, script_file = reads_stdin_script(inv.argv)
            if script_file:
                self.impact.not_covered(f"{tool} <script>")
        for r, body, body_subs in inv.heredocs:
            if shell_stdin or self.payload_reads_stdin(inv):
                self.subshell(body, state, depth)        # the shell runs the body
            else:
                for s in body_subs:                      # the outer shell expands $( )
                    self.subshell(s, state, depth)
        self.redirect(inv, state)
        before = state.copy()

        if tool == "cd":
            return self.cd(inv, state)
        if tool in ("pushd", "popd"):
            state.cwd = None
            return state, before
        if tool in _VAR_BUILTINS:
            for w in inv.argv[1:]:
                if "=" in w.raw and not w.value.startswith("-"):
                    self.assign(w, state)
            return state, None
        if tool == "unset":
            for w in inv.argv[1:]:
                if not w.value.startswith("-"):
                    state.vars[w.value] = ""
            return state, None
        if tool in ("true", ":"):
            return state, None
        if tool == "false":
            return None, state
        if inv.powershell:
            self.impact.not_covered("powershell")
            return state, before
        if inv.payload is not None:
            self.subshell(inv.payload, state, depth)
            return state, self.merge(before, state)
        if tool in SHELLS:
            if shell_stdin and piped_in and not inv.heredocs:
                self.impact.not_understood(inv.text, "a shell runs whatever the pipe feeds it")
            return state, self.merge(before, state)
        if tool == "trap":
            args = [w.value for w in inv.argv[1:] if w.value != "--"]
            if (len(args) >= 2 and args[0] not in ("-", "")
                    and not (args[0].startswith("-") and len(args[0]) > 1 and "p" in args[0])):
                self.impact.not_understood(inv.text, "code registered to run later")
            return state, before
        rules = self.table.get(tool)
        if not rules and tool in LAZY_FAMILIES:
            rules = self.load_family(tool)
        if not rules:
            if tool not in READ_ONLY:
                self.impact.not_covered(tool)
            return state, before
        for rule in rules:
            if rule.partial:
                # The file side is modelled; the rest (a network request, a
                # remote host) is C2's, and the prediction says so, so the row
                # stays OUT_OF_SCOPE instead of looking covered and harmless.
                if rule.partial == "network":
                    self.impact.not_covered(f"{tool} (network)")
            parsed = parse_options(inv.argv[1:], rule.options)
            if not applies(rule, parsed):
                continue
            if "xargs" in inv.wrappers:
                self.impact.not_understood(inv.text, "xargs adds operands it reads from stdin")
            if rule.resolver:
                resolvers = self.untimed(_resolvers)          # an import, not analysis
                self.upstream = upstream
                try:
                    getattr(resolvers, rule.resolver)(self, inv, parsed, state, tool)
                finally:
                    self.upstream = None
                continue
            paths = self.paths(parsed.operands, state, inv)
            for eff in rule.effects:
                if eff.kind == DELETE:
                    for p in paths:
                        self.delete(state, p, eff, parsed.flags)
                elif eff.kind == CREATE:
                    for p in paths:
                        self.create(state, p)
                elif eff.kind == MKDIR:
                    for p in paths:
                        self.mkdir(state, p, "parents" in parsed.flags)
        return state, self.merge(before, state)

    def untimed(self, fn):
        """Run `fn` outside the budget: the budget measures ANALYSIS, and a
        lazy import met mid-line must not eat it (review C2a, CR3)."""
        with self.budget.paused():
            return fn()

    def load_family(self, tool: str) -> List[Rule]:
        """A family's rules, imported the first time one of its tools is met."""
        for rule in self.untimed(lambda: family_rules(LAZY_FAMILIES[tool])):
            for t in rule.tools:
                if rule not in self.table.setdefault(t, []):
                    self.table[t].append(rule)
        return self.table.get(tool, [])

    def payload_reads_stdin(self, inv: Invocation) -> bool:
        if inv.payload is None:
            return False
        for cm in inv.payload.commands:
            argv = cm.argv
            if argv and os.path.basename(argv[0].value) in SHELLS and reads_stdin_script(argv)[0]:
                return True
        return False

    def redirect(self, inv: Invocation, state: State) -> None:
        for r in inv.redirects:
            if r.op not in _WRITES or r.target is None:
                continue
            if r.op == ">&" and not r.target.expands and (r.target.value.isdigit()
                                                          or r.target.value == "-"):
                continue                                 # fd duplication
            for p in self.paths([r.target], state, inv):
                self.write(state, p, r.op in (">>", "&>>"))     # /dev: see device()

    def assign(self, w, state: State) -> None:
        name, _eq, _rest = w.raw.partition("=")
        if name.endswith("+"):
            state.vars[name[:-1]] = None                 # += appends to what we may not know
            return
        value_raw = w.raw[len(name) + 1:]
        from ..model import Word
        value = Word(value_raw, value_raw, 0, 0, expands="$" in value_raw or "`" in value_raw)
        try:
            state.vars[name] = " ".join(expand(value, state.vars, state.cwd,
                                               lambda p: [], plain=True))
        except Unknown:
            state.vars[name] = None

    def cd(self, inv: Invocation, state: State) -> Tuple[Optional[State], Optional[State]]:
        args = [w for w in inv.argv[1:] if w.value not in ("-L", "-P", "-e", "-@")]
        if not args:
            target: Optional[str] = os.path.expanduser("~")
        elif args[0].value == "-" and not args[0].expands:
            target = state.prev
        else:
            try:
                fields = expand(args[0], state.vars, state.cwd, lambda p: [], plain=True)
            except Unknown:
                fields = []
            f = fields[0] if fields else None
            if f is not None:
                hf = _host_path(f)
                if hf is None:
                    f = None
                else:
                    f = hf
            if f is None or (not os.path.isabs(f) and (state.cwd is None or os.environ.get("CDPATH"))):
                target = None
            else:
                target = os.path.normpath(os.path.join(state.cwd or "", f))
        if target is None:
            moved = state.copy()
            moved.cwd = None
            return moved, state
        n = self.node(state, target)
        if n.exists and (n.is_dir or os.path.isdir(target)):
            moved = state.copy()
            moved.prev, moved.cwd = state.cwd, target
            return moved, None
        return None, state                               # cd fails: nothing moves

    def finish(self, final: State) -> Impact:
        imp = self.impact
        # A path that did not exist before and may exist at the end: new
        # content, or a backup holding old content under a new name.
        imp.creates = {p for p in imp.created
                       if self.node(final, p).exists and not self.real_node(p).exists}
        return imp


# A line that is SQL, not shell: the check door with --db/--db-url, or an
# UPPERCASE statement keyword first (no shell command is spelled that way).
# A set lookup, not a regex: compiling a 60-way alternation cost ~1 ms of
# import on every hook call (measured, C2a).
_SQL_LEAD = frozenset((
    "SELECT INSERT UPDATE DELETE DROP TRUNCATE ALTER CREATE REPLACE WITH MERGE UPSERT GRANT "
    "REVOKE PRAGMA VACUUM ATTACH DETACH EXPLAIN COPY CALL SHOW BEGIN COMMIT ROLLBACK RENAME "
    "COMMENT REINDEX ANALYZE VALUES TABLE USE LOCK DO EXECUTE PREPARE DESCRIBE LOAD OPTIMIZE "
    "REPAIR FLUSH KILL SAVEPOINT RELEASE START NOTIFY LISTEN REFRESH CLUSTER DISCARD RESET "
    "CHECKPOINT IMPORT HANDLER").split())


def _is_bare_sql(command: str, sql_target: Tuple[Optional[str], Optional[str]]) -> bool:
    head = command.lstrip(" \t\r\n(").split(None, 1)
    first = head[0].rstrip(";(") if head else ""
    return (first.upper() if any(sql_target) else first) in _SQL_LEAD


def _resolvers():
    from . import resolvers
    return resolvers


def preload(command: str, sql_target: Tuple[Optional[str], Optional[str]]) -> None:
    """Import the lazy families (and warm their patterns) the line names,
    BEFORE the budget's clock starts: every hook call is a fresh process, and
    a cold import inside a 10 ms budget lost 6/6 psql predictions under load
    (review C2a, CR3). Words are read from the raw text, so a tool inside
    $( ), a -c payload or a pipe is seen too."""
    words = {os.path.basename(w.strip("'\"`$();|&{}<>")) for w in command.split()}
    families = {LAZY_FAMILIES[w] for w in words if w in LAZY_FAMILIES}
    for module in families:
        family_rules(module)
    if families or _is_bare_sql(command, sql_target):
        from . import sql, sqlclients                          # noqa: F401
        for tool, dialect in (("sqlite3", "sqlite"), ("psql", "postgres"), ("mysql", "mysql"),
                              ("mariadb", "mysql")):
            if tool in words:
                sql.warm(dialect)
        if _is_bare_sql(command, sql_target):
            sql.warm("postgres")
            sql.warm("sqlite")


def simulate(command: str, rules: Tuple[Rule, ...] = RULES, cwd: Optional[str] = None,
             budget_ms: float = 10.0,
             sql_target: Tuple[Optional[str], Optional[str]] = (None, None)) -> Impact:
    """The Impact of `command` if it ran now, from `cwd` (default: here).
    `sql_target` is the check door's (--db, --db-url): with it, or when the
    line starts with an UPPERCASE SQL keyword, the line is SQL, not shell
    (C2a, Q3) - a shell would parse `WHERE id < 10` as a redirection."""
    preload(command, sql_target)
    world = World(rules, Budget(budget_ms))
    world.sql_target = sql_target
    here = os.path.abspath(cwd or os.getcwd())
    start = State({}, here, here, {})
    if _is_bare_sql(command, sql_target):
        from .sqlclients import run_bare_sql                  # lazy: SQL lines only
        if any(sql_target):
            run_bare_sql(world, command, start)                # --db / --db-url: it IS SQL
            return world.finish(start)
        # No --db: the line may be SQL (the check door) or shell (the agent's
        # Bash tool, where `SELECT 1; rm -rf dir` runs rm). Both readings,
        # merged (review C2a, CR1; may-semantics as ruling R3).
        run_bare_sql(world, command, start.copy(), dual=True)
        final = world.run_script(parse(command.replace("\r\n", "\n")), start, 0)
        world.impact.uncovered[:] = [u for u in world.impact.uncovered if u not in _SQL_LEAD]
        return world.finish(final)
    final = world.run_script(parse(command.replace("\r\n", "\n")), start, 0)
    return world.finish(final)
