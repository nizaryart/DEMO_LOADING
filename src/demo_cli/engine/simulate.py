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

import fnmatch
import glob as _glob
import os
import stat
import time
from typing import Dict, FrozenSet, List, Optional, Tuple

from ..model import Script, parse
from .effects import CREATE, DELETE, MOVE, OVERWRITE, TRUNCATE, Impact
from .invocation import Invocation, build, parse_options, reads_stdin_script
from .rules import READ_ONLY, RULES, SHELLS, Rule, applies, rules_by_tool
from .words import Unknown, expand

NEW = ""                     # the origin of content this command itself makes
MAX_GLOB = 10_000
MAX_DEPTH = 8
_WRITES = (">", ">|", "&>", ">&", ">>", "&>>")
_VAR_BUILTINS = ("export", "readonly", "declare", "typeset", "local")


class BudgetExceeded(Exception):
    pass


class Budget:
    def __init__(self, ms: float):
        self.deadline = time.perf_counter() + ms / 1000.0

    def check(self) -> None:
        if time.perf_counter() > self.deadline:
            raise BudgetExceeded()


class Node:
    """One path's state. Treated as immutable: every change makes a new Node."""
    __slots__ = ("exists", "is_dir", "origins", "moved_from")

    def __init__(self, exists: bool, is_dir: bool = False,
                 origins: FrozenSet[str] = frozenset(), moved_from: Optional[str] = None):
        self.exists = exists
        self.is_dir = is_dir
        self.origins = origins
        self.moved_from = moved_from      # a real directory whose children now live here


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
                            x.origins | y.origins, x.moved_from or y.moved_from)
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
                if os.path.isabs(f):
                    out.append(os.path.normpath(f))
                elif state.cwd is None:
                    self.impact.not_understood(inv.text, "the working directory is unknown")
                else:
                    out.append(os.path.normpath(os.path.join(state.cwd, f)))
        return out

    # ---- effects ------------------------------------------------------------
    def write(self, state: State, path: str, appending: bool) -> None:
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
        self.lose(n, DELETE)
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

    def move(self, state: State, paths: List[str], parsed, inv: Invocation) -> None:
        target = parsed.options.get("target")
        if target:
            dests = self.paths(target[:1], state, inv)
            if not dests:
                return
            dest, srcs, into = dests[0], paths, True
        else:
            if len(paths) < 2:
                return
            dest, srcs = paths[-1], paths[:-1]
            dn = self.node(state, dest)
            into = dn.exists and dn.is_dir
            if not into and len(srcs) > 1:
                return                                   # mv refuses
        for src in srcs:
            sn = self.node(state, src)
            if not sn.exists:
                continue
            dst = os.path.join(dest, os.path.basename(src)) if into else dest
            if dst == src:
                continue
            dn = self.node(state, dst)
            if dn.exists:
                if dn.is_dir != sn.is_dir:
                    continue
                self.lose(dn, OVERWRITE)
            moved_from = sn.moved_from or (src if sn.is_dir and NEW not in sn.origins else None)
            state.nodes[dst] = Node(True, sn.is_dir, sn.origins, moved_from)
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
            done, failed = self.run(inv, member, depth, piped_in=k > 0)
            state = self.merge(done, failed) or member
        state.cwd, state.prev, state.vars = pre.cwd, pre.prev, dict(pre.vars)
        return state, self.merge(pre, state)

    def subshell(self, script: Script, state: State, depth: int) -> None:
        """Run `script` with a copy of cwd and variables; keep its file effects."""
        end = self.run_script(script, state.copy(), depth + 1)
        state.nodes = end.nodes

    def run(self, inv: Invocation, state: State, depth: int,
            piped_in: bool) -> Tuple[Optional[State], Optional[State]]:
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
        rules = self.table.get(tool)
        if not rules:
            if tool not in READ_ONLY:
                self.impact.not_covered(tool)
            return state, before
        for rule in rules:
            parsed = parse_options(inv.argv[1:], rule.options)
            if not applies(rule, parsed):
                continue
            if "xargs" in inv.wrappers:
                self.impact.not_understood(inv.text, "xargs adds operands it reads from stdin")
            paths = self.paths(parsed.operands, state, inv)
            for eff in rule.effects:
                if eff.kind == DELETE:
                    for p in paths:
                        self.delete(state, p, eff, parsed.flags)
                elif eff.kind == CREATE:
                    for p in paths:
                        self.create(state, p)
                elif eff.kind == MOVE:
                    self.move(state, paths, parsed, inv)
        return state, self.merge(before, state)

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
                if not p.startswith("/dev/"):
                    self.write(state, p, r.op in (">>", "&>>"))

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
        imp.creates = {p for p in imp.created
                       if self.node(final, p).exists and NEW in self.node(final, p).origins}
        return imp


def simulate(command: str, rules: Tuple[Rule, ...] = RULES, cwd: Optional[str] = None,
             budget_ms: float = 10.0) -> Impact:
    """The Impact of `command` if it ran now, from `cwd` (default: here)."""
    world = World(rules, Budget(budget_ms))
    here = os.path.abspath(cwd or os.getcwd())
    start = State({}, here, here, {})
    final = world.run_script(parse(command.replace("\r\n", "\n")), start, 0)
    return world.finish(final)
