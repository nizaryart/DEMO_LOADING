"""What a few read-only commands print, so `$( )` can be read (Idea 1, I1b).

`rm $(cat list.txt)` deletes the names list.txt holds. The engine reads
list.txt through the simulation - as this line leaves it - and hands the
text to words.expand, which splits and globs it exactly as bash does. Only
commands whose output follows from what the line shows are read here; for
anything else the substitution stays UNKNOWN, as before.

Each answer is bash's, checked against bash 5 (and dash where they differ):
trailing newlines are removed by the caller's rules, NUL bytes are refused,
echo with a backslash is refused because dash's echo reads escapes.
"""
from __future__ import annotations

import os
import re
from typing import List

from .invocation import build
from .words import Unknown, expand

MAX_OUTPUT = 64 * 1024
PURE = frozenset({"cat", "echo", "printf", "pwd", "basename", "dirname"})
_EXTERNAL = frozenset({"cat", "basename", "dirname"})          # found on PATH
_DRIVE = re.compile(r"^([A-Za-z]):\\(.*)$")
_TRAILING_CRLF = re.compile(r"(?:\r?\n)+\Z")


def _no_glob(_pattern: str) -> List[str]:
    raise Unknown("a glob inside $( )")


def output(w, script, state) -> str:
    """What `script` prints, trailing newlines removed. Raises Unknown."""
    invs = build(script)
    if len(invs) != 1 or invs[0].sep not in ("", ";", "\n"):
        raise Unknown("more than one command")
    inv = invs[0]
    if (inv.clause or inv.prefix or inv.wrappers or inv.subs or inv.payload is not None
            or inv.powershell or inv.heredocs or inv.depth):
        raise Unknown("a command this engine does not read")
    if "PATH" in state.vars:
        raise Unknown("PATH is changed on this line")
    if w.redefined:
        raise Unknown(f"`{w.redefined}` on this line may change what a name runs")
    if not inv.argv:                                   # $(<FILE)
        if (len(inv.redirects) != 1 or inv.redirects[0].op != "<"
                or inv.redirects[0].fd is not None or inv.redirects[0].target is None):
            raise Unknown("a command this engine does not read")
        text = _cat(w, state, _args(w, state, [inv.redirects[0].target]))
        return _finish(text)
    for r in inv.redirects:
        t = r.target
        if not (r.fd == "2" and r.op in (">", ">>") and t is not None
                and not t.expands and t.value == "/dev/null"):
            raise Unknown("a redirection inside $( )")
    head = inv.argv[0]
    tool = head.value
    if head.expands or "/" in tool or "\\" in tool or tool not in PURE:
        raise Unknown("a command this engine does not read")
    if tool in w.functions:
        raise Unknown(f"{tool} is a function defined on this line")
    args = _args(w, state, inv.argv[1:])
    if tool == "cat":
        if args[:1] == ["--"]:
            args = args[1:]
        if any(a.startswith("-") for a in args):
            raise Unknown("cat with options")
        text = _cat(w, state, args)
    elif tool == "echo":
        text = _echo(args)
    elif tool == "printf":
        text = _printf(args)
    elif tool == "pwd":
        text = _pwd(args, state)
    elif tool == "basename":
        text = _basename(args)
    else:
        text = _dirname(args)
    return _finish(text)


def _finish(text: str, windows: bool = os.name == "nt") -> str:
    """The output as the substitution gives it: trailing newlines removed.
    Git Bash (MSYS bash 5.2.37, VERIFIED) also removes the \r of a trailing
    \r\n - a CRLF file gives `b.txt`, not `b.txt\r` - while Linux bash keeps
    it. Every other \r stays on both."""
    if "\x00" in text:
        raise Unknown("the output holds a NUL byte")
    if len(text) > MAX_OUTPUT:
        raise Unknown(f"the output is larger than {MAX_OUTPUT // 1024} KiB")
    if windows:
        return _TRAILING_CRLF.sub("", text)
    return text.rstrip("\n")


def _args(w, state, words) -> List[str]:
    out: List[str] = []
    for word in words:
        fields = expand(word, state.vars, state.cwd, _no_glob)
        if not fields and word.quoted:
            raise Unknown("an empty argument inside $( )")
        out.extend(fields)
    return out


def _cat(w, state, names: List[str]) -> str:
    from .simulate import NEW, _host_path
    if not names:
        raise Unknown("cat reads its standard input")
    if w.root is None:
        raise Unknown("the project root is unknown")
    root = os.path.realpath(w.root)
    parts = []
    for name in names:
        if name == "-":
            raise Unknown("cat reads its standard input")
        p = _host_path(name)
        if p is None:
            raise Unknown("a Git Bash path that cannot be mapped to Windows")
        if not os.path.isabs(p):
            if state.cwd is None:
                raise Unknown("the working directory is unknown")
            p = os.path.join(state.cwd, p)
        p = os.path.normpath(p)
        q = p
        while True:                                    # the line may have changed it: a
            if q in w.impact.touched:                  # failed rm or mv leaves "may exist"
                raise Unknown(f"{os.path.basename(p)} is changed earlier on this line")
            if os.path.dirname(q) == q:
                break
            q = os.path.dirname(q)
        for origin in w.node(state, p).origins - {NEW}:
            real = os.path.realpath(origin)
            try:
                inside = os.path.commonpath([real, root]) == root
            except ValueError:
                inside = False
            if not inside:
                raise Unknown(f"{os.path.basename(p)} is outside the project")
        text, why = w.read_text(state, p, MAX_OUTPUT, raw=True)
        if text is None:
            raise Unknown(why)
        if "�" in text:
            raise Unknown(f"{os.path.basename(p)} is not UTF-8 text")
        parts.append(text)
    return "".join(parts)


def _echo(args: List[str]) -> str:
    newline = True
    while args and re.fullmatch(r"-[neE]+", args[0]):
        if args[0] != "-n":
            raise Unknown("echo with -e or -E")          # dash prints them as text
        newline = False
        args = args[1:]
    if any("\\" in a for a in args):
        raise Unknown("echo with a backslash")           # dash's echo reads escapes
    return " ".join(args) + ("\n" if newline else "")


_ESCAPES = {"n": "\n", "t": "\t", "\\": "\\"}


def _printf(args: List[str]) -> str:
    if not args or args[0].startswith("-"):
        raise Unknown("printf with options")
    fmt, rest = args[0], args[1:]
    pieces: list = []                                    # str, or None for a %s slot
    i = 0
    while i < len(fmt):
        c = fmt[i]
        if c == "\\":
            nxt = fmt[i + 1:i + 2]
            if nxt not in _ESCAPES:
                raise Unknown("a printf escape this engine does not read")
            pieces.append(_ESCAPES[nxt])
            i += 2
        elif c == "%":
            nxt = fmt[i + 1:i + 2]
            if nxt == "%":
                pieces.append("%")
            elif nxt == "s":
                pieces.append(None)
            else:
                raise Unknown("a printf conversion this engine does not read")
            i += 2
        else:
            pieces.append(c)
            i += 1
    slots = pieces.count(None)
    if slots == 0:
        return "".join(pieces)
    out = []
    while True:
        take, rest = rest[:slots], rest[slots:]
        take += [""] * (slots - len(take))
        it = iter(take)
        out.append("".join(next(it) if p is None else p for p in pieces))
        if not rest:
            break
    return "".join(out)


def _pwd(args: List[str], state) -> str:
    if args:
        raise Unknown("pwd with arguments")
    cwd = state.cwd
    if cwd is None:
        raise Unknown("the working directory is unknown")
    if os.name == "nt":
        m = _DRIVE.match(cwd)
        if not m:
            raise Unknown("a working directory Git Bash names differently")
        rest = m.group(2).replace("\\", "/").rstrip("/")
        cwd = f"/{m.group(1).lower()}" + (f"/{rest}" if rest else "")
    return cwd + "\n"


def _plain_operands(tool: str, args: List[str]) -> List[str]:
    if args[:1] == ["--"]:
        args = args[1:]
    if any(a.startswith("-") and a != "-" for a in args):
        raise Unknown(f"{tool} with options")
    if any("\\" in a for a in args):
        raise Unknown(f"{tool} with a backslash")
    return args


def _basename(args: List[str]) -> str:
    args = _plain_operands("basename", args)
    if len(args) not in (1, 2):
        raise Unknown("basename with that many operands")
    s = args[0]
    if s == "":
        return "\n"
    t = s.rstrip("/")
    base = "/" if t == "" else t.rsplit("/", 1)[-1]
    if len(args) == 2 and base != args[1] and base.endswith(args[1]) and args[1]:
        base = base[:-len(args[1])]
    return base + "\n"


def _dirname(args: List[str]) -> str:
    args = _plain_operands("dirname", args)
    if not args:
        raise Unknown("dirname without an operand")
    out = []
    for s in args:
        t = s.rstrip("/")
        if s == "":
            d = "."
        elif t == "":
            d = "/"
        elif "/" not in t:
            d = "."
        else:
            d = t[:t.rindex("/")].rstrip("/") or "/"
        out.append(d + "\n")
    return "".join(out)
