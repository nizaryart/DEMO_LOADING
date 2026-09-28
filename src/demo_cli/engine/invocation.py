"""From model.py's parsed Commands to Invocations: one per command that runs.

Built from the parse, never from text. The command word, its arguments, its
redirections, the prefix assignments, the wrappers it sits behind (sudo,
xargs, ...) and every nested script it runs - $( ), `...`, <( ), a -c
payload, env -S, a heredoc fed to a shell - each stay attached to the
command they belong to, which is what the simulation needs and what a
flattened text cannot give back.
"""
from __future__ import annotations

import os
import re
from typing import FrozenSet, List, Optional, Tuple

from ..model import Command, Redirect, Script, Word, _ASSIGN, _subs_in, parse
from ..classify import _WRAPPERS
from .rules import OptionSpec


class Invocation:
    __slots__ = ("command", "line", "argv", "redirects", "prefix", "wrappers", "subs",
                 "payload", "powershell", "heredocs", "sep", "depth", "clause")

    def __init__(self, command: Command, line: str, argv: List[Word],
                 redirects: List[Redirect], prefix: List[Word], wrappers: List[str],
                 subs: List[Script], payload: Optional[Script], powershell: bool,
                 heredocs: List[Tuple[Redirect, Script, List[Script]]], sep: str,
                 depth: int, clause: Optional[str]):
        self.command = command
        self.line = line
        self.argv = argv                  # argv[0] is the command word
        self.redirects = redirects
        self.prefix = prefix              # leading NAME=value words
        self.wrappers = wrappers          # sudo, xargs, env, nohup, ...
        self.subs = subs                  # $( ) / `` / <( ): run BEFORE the command
        self.payload = payload            # sh -c "...", env -S '...', cmd /c
        self.powershell = powershell      # a powershell -Command payload (C)
        self.heredocs = heredocs          # (redirect, body as a script, body $( )s)
        self.sep = sep
        self.depth = depth
        self.clause = clause              # for / case / select / function header

    @property
    def text(self) -> str:
        """The command's own source text, for receipts and reasons."""
        cm = self.command
        words = [w for w in cm.words] + [r.target for r in cm.redirects if r.target]
        if not words:
            return ""
        a = min([w.start for w in words] + [r.start for r in cm.redirects])
        b = max(w.end for w in words)
        return self.line[a:b].strip()


def build(script: Script) -> List[Invocation]:
    out: List[Invocation] = []
    for cm in script.commands:
        pa, pb = cm.payload
        subs = [inner for k, w in enumerate(cm.words) if not (pa <= k < pb)
                for _a, _b, inner in w.subs]
        subs += [inner for r in cm.redirects if r.target for _a, _b, inner in r.target.subs]
        heredocs = []
        for r in cm.redirects:
            hd = r.heredoc
            if hd is None:
                continue
            body_subs = [] if hd.quoted else [inner for _a, _b, inner in _subs_in(hd.body)]
            heredocs.append((r, parse(hd.body), [parse(s) for s in body_subs]))
        head = cm.words[:cm.cmd_index]
        out.append(Invocation(
            command=cm, line=script.line, argv=list(cm.argv), redirects=list(cm.redirects),
            prefix=[w for w in head if _ASSIGN.match(w.raw)],   # X='a b' is still X=
            wrappers=[os.path.basename(w.value) for w in head
                      if not w.expands and os.path.basename(w.value) in _WRAPPERS],
            subs=[parse(s) for s in subs],
            payload=cm.nested, powershell=cm.nested_ps is not None,
            heredocs=heredocs, sep=cm.sep, depth=cm.depth,
            clause=(cm.words[0].value if cm.clause and cm.words else None),
        ))
    return out


class Parsed:
    __slots__ = ("flags", "options", "operands", "unknown_options", "early_flags")

    def __init__(self, flags: FrozenSet[str], options: dict, operands: List[Word],
                 unknown_options: Optional[List[str]] = None,
                 early_flags: FrozenSet[str] = frozenset()):
        self.flags = flags
        self.options = options                    # canonical -> [Word]
        self.operands = operands
        self.unknown_options = unknown_options or []
        self.early_flags = early_flags            # seen before the first operand


def parse_options(args: List[Word], spec: OptionSpec) -> Parsed:
    """GNU-style option parsing against `spec`: clusters (-rf), --opt=value,
    `--` ends options, options may follow operands. Judged on each word's
    VALUE (quotes removed), as the program receives it. A word that still
    expands ($X) is an operand: what it becomes is the simulation's call. An
    unknown option is kept, never silently dropped."""
    flags, options, operands, unknown = set(), {}, [], []
    early = None
    i, done = 0, False
    while i < len(args):
        w = args[i]
        v = w.value
        i += 1
        if done or w.expands or not v.startswith("-") or v == "-":
            if early is None:
                early = frozenset(flags)
            operands.append(w)
            if not spec.permute:
                done = True
            continue
        if v == "--":
            done = True
            continue
        if v.startswith("--"):
            name, eq, rest = v.partition("=")
            if name in spec.values:
                if eq:
                    options.setdefault(spec.values[name], []).append(Word(rest, rest, w.start, w.end))
                elif i < len(args):
                    n = spec.arity.get(spec.values[name], 1)
                    options.setdefault(spec.values[name], []).extend(args[i:i + n])
                    i += n
            elif name in spec.flags:
                flags.add(spec.flags[name])
                if eq:                      # --backup=numbered, --update=none
                    options.setdefault(spec.flags[name], []).append(Word(rest, rest, w.start, w.end))
            else:
                unknown.append(v)
            continue
        if len(v) > 2 and (v in spec.flags or v in spec.values):     # wget -nc, -nd
            if v in spec.flags:
                flags.add(spec.flags[v])
            elif i < len(args):
                n = spec.arity.get(spec.values[v], 1)
                options.setdefault(spec.values[v], []).extend(args[i:i + n])
                i += n
            continue
        body = v[1:]
        for j, ch in enumerate(body):
            short = "-" + ch
            if short in spec.attached:
                rest = body[j + 1:]
                flags.add(spec.attached[short])
                options.setdefault(spec.attached[short], []).append(Word(rest, rest, w.start, w.end))
                break
            if short in spec.values:
                rest = body[j + 1:]
                if rest:
                    options.setdefault(spec.values[short], []).append(Word(rest, rest, w.start, w.end))
                elif i < len(args):
                    options.setdefault(spec.values[short], []).append(args[i])
                    i += 1
                break
            if short in spec.flags:
                flags.add(spec.flags[short])
            else:
                unknown.append(short)
    return Parsed(frozenset(flags), options, operands, unknown,
                  frozenset(flags) if early is None else early)


_C_FLAG = re.compile(r"^-[A-Za-z]*c[A-Za-z]*$")


def reads_stdin_script(argv: List[Word]) -> Tuple[bool, bool]:
    """(runs its stdin as a script?, names a script file?) for a shell."""
    for w in argv[1:]:
        v = w.value
        if v == "--":
            continue
        if v.startswith("-") or v.startswith("+"):
            if _C_FLAG.match(v):
                return False, False          # -c: the payload is the script
            continue
        return False, True                   # first operand: a script file
    return True, False
