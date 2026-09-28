"""The command model: parse a POSIX command line ONCE.

classify._effective_segments serves its result to the classifier AND to
target resolution, so the two read one parse instead of each re-deriving
shell syntax from raw text - the source of most defects found in the audit
and review of 2026-09-26/27 (two parsers answering one question
differently).

What it models, and what the current string layer does not:
  * words with their quoting, so "text" and "code" are told apart by
    structure, not by a regex that happens to ignore quotes;
  * command substitutions $( ) and `...` and process substitutions <( ) as
    NESTED SCRIPTS - commands that run, found by parsing;
  * heredoc bodies attached to the redirection that opened them;
  * keywords, assignments and wrappers (sudo, nohup, xargs, ...) resolved
    to the real command word;
  * comments, escaped separators, operators inside $( ).

PowerShell is not modelled in this slice.
"""
from __future__ import annotations

import functools
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .classify import (POSIX, POWERSHELL, _WRAPPERS, _WRAPPER_LONG_VALUE,
                       unwrap_nested)

# --------------------------------------------------------------------------
# Data
# --------------------------------------------------------------------------


@dataclass
class Script:
    line: str
    commands: List["Command"] = field(default_factory=list)


@dataclass
class Word:
    raw: str                     # exact source text
    value: str                   # quotes removed, expansions left as written
    start: int                   # offsets into Script.line
    end: int
    quotes: List[Tuple[int, int, str]] = field(default_factory=list)  # (start, end, kind)
    subs: List[Tuple[int, int, str]] = field(default_factory=list)    # (start, end, inner)
    expands: bool = False        # $var, ${..}, $( ), `..` - value not static

    @property
    def quoted(self) -> bool:
        return bool(self.quotes)


@dataclass
class Heredoc:
    delimiter: str
    quoted: bool
    strip_tabs: bool
    body: str = ""


@dataclass
class Redirect:
    op: str
    fd: Optional[str]
    target: Optional[Word]
    heredoc: Optional[Heredoc] = None
    start: int = 0               # offset of the fd / operator in Script.line


@dataclass
class Command:
    words: List[Word] = field(default_factory=list)
    redirects: List[Redirect] = field(default_factory=list)
    sep: str = ""                # what follows: ; & && || | |& \n ;; or ""
    cmd_index: int = 0           # first word of the real command
    clause: bool = False         # for/case/select/function header: nothing runs
    nested: Optional[Script] = None       # sh -c "..." payload
    nested_ps: Optional[str] = None       # powershell -Command payload (not modelled)
    payload: Tuple[int, int] = (0, 0)     # word index range holding the payload
    depth: int = 0               # ( ) subshell nesting where the command starts

    @property
    def argv(self) -> List[Word]:
        return self.words[self.cmd_index:]

    @property
    def start(self) -> int:
        items = [w.start for w in self.argv] + [r.start for r in self.redirects]
        return min(items) if items else 0

    @property
    def end(self) -> int:
        items = [w.end for w in self.words] + [
            r.target.end for r in self.redirects if r.target is not None]
        return max(items) if items else 0


# --------------------------------------------------------------------------
# Lexer
# --------------------------------------------------------------------------

_BLANK = " \t"
_META = set(" \t\n;&|()<>")
_REDIRECT_OPS = ("<<<", "<<-", "&>>", "<<", ">>", ">|", ">&", "<&", "<>", "&>", "<", ">")


class _Lexer:
    def __init__(self, s: str):
        self.s, self.i, self.n = s, 0, len(s)
        self.tokens: list = []              # ("w", Word) | ("op", op, fd) | ("r", op, fd)
        self.pending: List[Heredoc] = []

    # -- helpers ----------------------------------------------------------
    def _balanced(self, j: int, open_: str, close: str) -> int:
        """Index just past the `close` matching an already-consumed `open_`."""
        s, n, depth = self.s, self.n, 1
        while j < n and depth:
            ch = s[j]
            if ch == "\\":
                j += 2
                continue
            if ch == "'":
                k = s.find("'", j + 1)
                j = n if k == -1 else k + 1
                continue
            if ch == '"':
                j = self._dquote_end(j)
                continue
            if ch == "`":
                k = j + 1
                while k < n and s[k] != "`":
                    k += 2 if s[k] == "\\" else 1
                j = k + 1
                continue
            if ch == open_:
                depth += 1
            elif ch == close:
                depth -= 1
            j += 1
        return j

    def _dquote_end(self, j: int) -> int:
        """Index just past the double quote closing the one at j."""
        s, n = self.s, self.n
        k = j + 1
        while k < n and s[k] != '"':
            if s[k] == "\\":
                k += 2
            elif s.startswith("$(", k):
                k = self._balanced(k + 2, "(", ")")
            elif s[k] == "`":
                m = k + 1
                while m < n and s[m] != "`":
                    m += 2 if s[m] == "\\" else 1
                k = m + 1
            else:
                k += 1
        return min(k + 1, n)

    # -- words -------------------------------------------------------------
    def word(self) -> Word:
        s, n = self.s, self.n
        start = self.i
        val: List[str] = []
        w = Word(raw="", value="", start=start, end=start)
        while self.i < n:
            i = self.i
            c = s[i]
            if c in _META:
                if c in "<>" and i + 1 < n and s[i + 1] == "(" and i == start:
                    pass                                   # <( ) at word start
                else:
                    break
            if c == "\\":
                if i + 1 < n and s[i + 1] == "\n":
                    self.i += 2                            # continuation
                    continue
                if i + 1 < n:
                    val.append(s[i + 1])
                    w.quotes.append((i, i + 2, "escape"))
                self.i += 2
                continue
            if c == "'":
                k = s.find("'", i + 1)
                k = n if k == -1 else k
                w.quotes.append((i, min(k + 1, n), "single"))
                val.append(s[i + 1:k])
                self.i = min(k + 1, n)
                continue
            if c == "$" and i + 1 < n and s[i + 1] == "'":
                k = i + 2
                while k < n and s[k] != "'":
                    k += 2 if s[k] == "\\" else 1
                w.quotes.append((i, min(k + 1, n), "ansi"))
                val.append(s[i + 2:k])
                self.i = min(k + 1, n)
                continue
            if c == '"':
                k = self._dquote_end(i)
                inner = s[i + 1:k - 1]
                w.quotes.append((i, k, "double"))
                # substitutions inside double quotes still run
                self._collect_subs(i + 1, k - 1, w)
                if "$" in inner or "`" in inner:
                    w.expands = True
                # Inside double quotes a backslash escapes only $ ` " \ and a
                # newline. The VALUE is what the next program receives: in
                # bash -c "echo \$(rm y)" the inner bash is handed $(rm y).
                val.append(re.sub(r'\\([$`"\\\n])', r"\1", inner))
                self.i = k
                continue
            if c in "<>" and i + 1 < n and s[i + 1] == "(":
                k = self._balanced(i + 2, "(", ")")
                w.subs.append((i + 2, k - 1, s[i + 2:k - 1]))
                w.expands = True
                val.append(s[i:k])
                self.i = k
                continue
            if c == "$" and s.startswith("$((", i):
                k = self._balanced(i + 3, "(", ")")
                k = k + 1 if k < n and s[k] == ")" else k
                self._collect_subs(i + 3, k - 2, w)        # $(( $(cmd) ))
                w.expands = True
                val.append(s[i:k])
                self.i = k
                continue
            if c == "$" and i + 1 < n and s[i + 1] == "(":
                k = self._balanced(i + 2, "(", ")")
                w.subs.append((i + 2, k - 1, s[i + 2:k - 1]))
                w.expands = True
                val.append(s[i:k])
                self.i = k
                continue
            if c == "`":
                k = i + 1
                while k < n and s[k] != "`":
                    k += 2 if s[k] == "\\" else 1
                w.subs.append((i + 1, k, s[i + 1:k]))
                w.expands = True
                val.append(s[i:k + 1])
                self.i = min(k + 1, n)
                continue
            if c == "$" and i + 1 < n and s[i + 1] == "{":
                k = self._balanced(i + 2, "{", "}")
                self._collect_subs(i + 2, k - 1, w)        # ${x:-$(cmd)}
                w.expands = True
                val.append(s[i:k])
                self.i = k
                continue
            if c == "$" and i + 1 < n and (s[i + 1].isalnum() or s[i + 1] in "_@*#?-$!"):
                w.expands = True
            val.append(c)
            self.i += 1
        w.end = self.i
        w.raw = s[start:self.i]
        w.value = "".join(val)
        return w

    def _collect_subs(self, a: int, b: int, w: Word) -> None:
        s = self.s
        j = a
        while j < b:
            if s[j] == "\\":
                j += 2
            elif s.startswith("$((", j):
                k = self._balanced(j + 3, "(", ")") + 1
                self._collect_subs(j + 3, k - 2, w)
                j = k
            elif s.startswith("$(", j):
                k = self._balanced(j + 2, "(", ")")
                w.subs.append((j + 2, k - 1, s[j + 2:k - 1]))
                j = k
            elif s[j] == "`":
                k = j + 1
                while k < b and s[k] != "`":
                    k += 2 if s[k] == "\\" else 1
                w.subs.append((j + 1, k, s[j + 1:k]))
                j = k + 1
            else:
                j += 1

    # -- heredocs ----------------------------------------------------------
    def bodies(self) -> None:
        s, n = self.s, self.n
        for hd in self.pending:
            lines = []
            while self.i < n:
                k = s.find("\n", self.i)
                k = n if k == -1 else k
                line = s[self.i:k]
                self.i = k + 1
                if (line.lstrip("\t") if hd.strip_tabs else line) == hd.delimiter:
                    break
                lines.append(line)
            hd.body = "\n".join(lines)
        self.pending = []

    # -- the loop ----------------------------------------------------------
    def run(self) -> list:
        s, n = self.s, self.n
        while self.i < n:
            c = s[self.i]
            if c in _BLANK:
                self.i += 1
                continue
            if c == "\\" and s.startswith("\\\n", self.i):
                self.i += 2
                continue
            if c == "#":
                k = s.find("\n", self.i)
                self.i = n if k == -1 else k
                continue
            if c == "\n":
                self.tokens.append(("op", "\n", None))
                self.i += 1
                if self.pending:
                    self.bodies()
                continue
            fd = None
            op_start = self.i
            m = re.match(r"\d+(?=[<>])", s[self.i:])
            if m:
                fd = m.group(0)
                self.i += len(fd)
                c = s[self.i]
            if c in "<>" or (c == "&" and s.startswith(("&>>", "&>"), self.i)):
                if c in "<>" and self.i + 1 < n and s[self.i + 1] == "(" and fd is None:
                    self.tokens.append(("w", self.word()))
                    continue
                op = next(o for o in _REDIRECT_OPS if s.startswith(o, self.i))
                self.i += len(op)
                hd = None
                if op in ("<<", "<<-"):
                    while self.i < n and s[self.i] in _BLANK:
                        self.i += 1
                    if self.i < n and s[self.i] not in _META:
                        dw = self.word()
                        hd = Heredoc(dw.value, dw.quoted, op == "<<-")
                        self.pending.append(hd)
                        self.tokens.append(("r", op, fd, hd, op_start))
                        self.tokens.append(("w", dw))
                        continue
                self.tokens.append(("r", op, fd, hd, op_start))
                continue
            if fd is not None:                    # digits not followed by a redirect
                self.i -= len(fd)
            for op in (";;&", ";;", ";&", "&&", "||", "|&", ";", "&", "|", "(", ")"):
                if s.startswith(op, self.i):
                    self.i += len(op)
                    self.tokens.append(("op", {";;&": ";;", ";&": ";;"}.get(op, op), None))
                    break
            else:
                self.tokens.append(("w", self.word()))
                if self.i < n and self.tokens[-1][1].raw == "":
                    self.i += 1                   # defensive: never stall
        return self.tokens


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

_KEYWORDS = frozenset({"if", "then", "else", "elif", "fi", "do", "done", "while",
                       "until", "!", "{", "}", "esac"})
_CLAUSES = frozenset({"for", "select", "case", "function"})
_ASSIGN = re.compile(r"^[A-Za-z_]\w*\+?=")
_SHELLS = frozenset({"bash", "sh", "dash", "zsh", "ksh"})
_SEPS = frozenset({";", ";;", "&", "&&", "||", "|", "|&", "\n"})


_MAX_DEPTH = 8                                  # `bash -c "bash -c ..."` must end


def parse(line: str, dialect: str = POSIX, _depth: int = 0) -> Script:
    script = Script(line)
    if dialect != POSIX or _depth > _MAX_DEPTH:
        return script
    lx = _Lexer(line)
    toks = lx.run()
    cur = Command()
    subshell = 0
    k = 0

    def finish(sep: str) -> None:
        nonlocal cur
        if cur.words or cur.redirects:
            cur.sep = sep
            _resolve(cur, line, _depth)
            script.commands.append(cur)
        cur = Command()

    while k < len(toks):
        t = toks[k]
        if t[0] in ("w", "r") and not cur.words and not cur.redirects:
            # Where the command STARTS: `( cd a; rm b ); rm c` - cd and the
            # first rm run in a subshell whose cwd dies at `)`, and the shadow
            # engine (engine/simulate.py) must not let it leak into `rm c`.
            cur.depth = subshell
        if t[0] == "w":
            cur.words.append(t[1])
        elif t[0] == "r":
            op, fd = t[1], t[2]
            target = toks[k + 1][1] if k + 1 < len(toks) and toks[k + 1][0] == "w" else None
            if target is not None:
                k += 1
            cur.redirects.append(Redirect(op, fd, target, t[3], t[4]))
        else:
            op = t[1]
            if op == "(":
                if not cur.words:
                    subshell += 1
                # else: `name()` - a function definition header
            elif op == ")":
                if subshell:
                    subshell -= 1
                    finish(";")
                else:
                    cur = Command()               # a case pattern: nothing runs
            elif op in _SEPS:
                finish(op)
        k += 1
    finish("")
    return script


def _resolve(cmd: Command, line: str, depth: int = 0) -> None:
    """Find the real command word: past keywords, assignments, wrappers."""
    words = cmd.words
    i = 0
    if words and words[0].value == "function" and not words[0].quoted:
        i = 2                                   # `function NAME { body...`
    elif words and words[0].value in _CLAUSES and not words[0].quoted:
        cmd.clause = True
        cmd.cmd_index = len(words)
        return
    guard = 0
    while i < len(words) and guard < 64:
        guard += 1
        w = words[i]
        if not w.quoted and w.value in _KEYWORDS:
            i += 1
            continue
        if _ASSIGN.match(w.raw):                # X="a b" rm y: the value may be quoted
            i += 1
            continue
        name = os.path.basename(w.value) if not w.expands else ""
        if name in _WRAPPERS and not w.quoted:
            split = _env_split_string(words, i + 1) if name == "env" else None
            if split is not None:
                # `env -S 'rm -rf x'` splits that string into the command it
                # runs, then appends any words after it. Its value is a
                # script, not an option value to step over.
                payload, k = split
                cmd.cmd_index = i
                cmd.nested = parse(payload, POSIX, depth + 1)
                cmd.payload = (k, len(words))
                return
            j = _skip_wrapper_words(words, i + 1, name)
            if j is None:
                break
            i = j
            continue
        break
    cmd.cmd_index = i
    argv = cmd.argv
    if not argv:
        return
    name = os.path.basename(argv[0].value).lower()
    if name.endswith(".exe"):
        name = name[:-4]
    # nested shells: <shell> [opts] -<cluster with c> PAYLOAD
    if name in _SHELLS:
        # bash [options] -c COMMAND_STRING: the command string is the first
        # non-option argument, and -o / -O / --rcfile take a value. The text
        # parser required -c to follow options that take none, so
        # `bash -o pipefail -c "rm app.db"` was never unwrapped (ALLOW).
        have_c, j = False, 1
        while j < len(argv):
            v = argv[j].value
            if v in ("-o", "+o", "-O", "+O", "--rcfile", "--init-file"):
                j += 2
                continue
            if v == "--":
                j += 1
                break
            if v.startswith("--"):
                j += 1
                continue
            if v[:1] in ("-", "+") and len(v) > 1:
                have_c = have_c or "c" in v[1:]
                j += 1
                continue
            break
        if have_c and j < len(argv):
            cmd.nested = parse(argv[j].value, POSIX, depth + 1)
            cmd.payload = (cmd.cmd_index + j, cmd.cmd_index + j + 1)
        return
    if name == "cmd" and len(argv) > 2 and argv[1].value.lower() in ("/c", "/k"):
        # cmd.exe takes the rest of its words as one command line. Raw text,
        # not POSIX values - a backslash is a path separator there - with the
        # outer quotes stripped; redirections already sit outside the words.
        from .classify import _strip_quotes
        payload = _strip_quotes(" ".join(w.raw for w in argv[2:]))
        cmd.nested = parse(payload, POSIX, depth + 1)
        cmd.payload = (cmd.cmd_index + 2, len(cmd.words))
        return
    if name in ("powershell", "pwsh"):
        nested = unwrap_nested(line[argv[0].start:cmd.end])
        if nested and nested[0].strip():
            cmd.nested_ps = nested[0]
            cmd.payload = (cmd.cmd_index + 1, len(cmd.words))


def _env_split_string(words: List[Word], i: int) -> Optional[Tuple[str, int]]:
    """(command string, index of the -S word) when env's options hold
    -S / --split-string, else None. GNU getopt: `-S cmd`, `-Scmd`, `-iS cmd`,
    `--split-string cmd`, `--split-string=cmd`; -u and -C take a value."""
    k = i
    while k < len(words):
        w = words[k]
        v = w.value
        if v == "--" or not v.startswith("-") or v == "-":
            if _ASSIGN.match(w.raw) and not w.quoted:
                k += 1
                continue
            return None
        value, after = None, k + 1
        if v == "--split-string":
            value, after = (words[k + 1].value, k + 2) if k + 1 < len(words) else ("", k + 1)
        elif v.startswith("--split-string="):
            value = v.split("=", 1)[1]
        elif v.startswith("--"):
            after = k + 2 if v in _WRAPPER_LONG_VALUE else k + 1
        else:
            for j, ch in enumerate(v[1:], start=1):
                rest = v[j + 1:]
                if ch == "S":
                    if rest:
                        value = rest
                    elif k + 1 < len(words):
                        value, after = words[k + 1].value, k + 2
                    else:
                        value = ""
                    break
                if ch in "uC":
                    after = k + 1 if rest else k + 2
                    break
        if value is not None:
            tail = " ".join(x.raw for x in words[after:])
            return (value + (" " + tail if tail else "")).strip(), k
        k = after
    return None


def _skip_wrapper_words(words: List[Word], i: int, name: str) -> Optional[int]:
    opts = _WRAPPERS[name]
    while i < len(words):
        v = words[i].value
        if v == "--":
            return i + 1
        if name == "command" and v in ("-v", "-V"):
            return None
        if name == "env" and _ASSIGN.match(words[i].raw) and not words[i].quoted:
            i += 1
            continue
        if not v.startswith("-") or v == "-":
            break
        takes = (v in _WRAPPER_LONG_VALUE if v.startswith("--")
                 else len(v) == 2 and v[1] in opts)
        i += 2 if takes else 1
    if name == "timeout":
        i += 1
    return i if i <= len(words) else None


# --------------------------------------------------------------------------
# What runs: the units the rule table judges
# --------------------------------------------------------------------------

def _units(script: Script, outer_sep: str = "") -> List[Tuple[str, str, str, bool]]:
    """(text, dialect, separator, inert) for every command that RUNS: the
    top level, sh -c payloads, $( ) / backtick / <( ) substitutions, and
    heredoc bodies fed to a consumer that executes them."""
    from .classify import _data_sink, _effective_segments
    out: List[Tuple[str, str, str, bool]] = []
    line = script.line
    last = len(script.commands) - 1
    for idx, cm in enumerate(script.commands):
        sep = cm.sep or (outer_sep if idx == last else "")
        pa, pb = cm.payload
        subs = [s for k, w in enumerate(cm.words) if not (pa <= k < pb)
                for s in w.subs]
        subs += [s for r in cm.redirects if r.target for s in r.target.subs]
        for _a, _b, inner in subs:
            out += _units(parse(inner, POSIX))
        if cm.clause:
            continue
        if not cm.argv:
            if cm.redirects:                       # `> app.db` truncates
                out.append((line[cm.start:cm.end].strip(), POSIX, sep, False))
            continue
        if cm.nested is not None:
            inner_units = _units(cm.nested, sep)
            out += inner_units
            # A heredoc feeds the nested shell's stdin: `bash -c 'sh' <<EOF`
            # runs its body. Data only when the payload is one data sink.
            out += _heredoc_units(cm, len(inner_units) == 1 and inner_units[0][3])
            continue
        if cm.nested_ps is not None:
            out += [(s, d, sp, False) for s, d, sp in
                    _effective_segments(cm.nested_ps, POWERSHELL, False, 1, sep)]
            out += _heredoc_units(cm, False)
            continue
        a, b = cm.argv[0].start, cm.end
        text = _blanked(line, a, b, subs)          # subs are judged as their own units
        # A redirection written BEFORE the command word still applies to it:
        # `> app.db echo hi` truncates app.db. The unit starts at the command
        # word so anchored rules see it first; the prefix redirections follow.
        prefix = [_blanked(line, r.start, r.target.end if r.target else r.start + len(r.op), subs)
                  for r in cm.redirects if r.start < a]
        text = " ".join([text] + prefix).strip()
        inert = sep != "|" and _data_sink(text)
        out.append((text, POSIX, sep, inert))
        out += _heredoc_units(cm, inert)
    return out


def _blanked(line: str, a: int, b: int, subs) -> str:
    """line[a:b] with every substitution's inside replaced by `_`, same length."""
    text = list(line[a:b])
    for sa, sb, _inner in subs:
        for k in range(max(sa, a), min(sb, b)):
            text[k - a] = "_"
    return "".join(text).strip()


def _heredoc_units(cm: Command, inert: bool) -> List[Tuple[str, str, str, bool]]:
    """Units for the heredoc bodies feeding `cm`. `inert`: the consumer only
    prints or records its stdin, so the body is data, not commands."""
    out: List[Tuple[str, str, str, bool]] = []
    for r in cm.redirects:
        hd = r.heredoc
        if hd is None:
            continue
        # An unquoted delimiter: the outer shell expands $( ) and
        # backticks in the body whatever the consumer, so those run here.
        body_subs = [] if hd.quoted else _subs_in(hd.body)
        for _a, _b, inner in body_subs:
            out += _units(parse(inner, POSIX))
        if not inert:                              # the consumer runs the body
            chars = list(hd.body)
            for a, b, _inner in body_subs:         # already judged above
                chars[a:b] = "_" * (b - a)
            out += _units(parse("".join(chars), POSIX))
    return out


def _subs_in(text: str) -> List[Tuple[int, int, str]]:
    holder = Word("", "", 0, 0)
    _Lexer(text)._collect_subs(0, len(text), holder)
    return holder.subs


@functools.lru_cache(maxsize=512)
def posix_units(cmd: str, outer_sep: str = "") -> Tuple[Tuple[str, str, str], ...]:
    """(text, dialect, separator) for every command in `cmd` that runs - the
    one parse classify._effective_segments serves to the classifier AND to
    target resolution. Cached: one evaluation asks for it about seven times."""
    return tuple((t, d, sp) for t, d, sp, _f in
                 _units(parse(cmd.replace("\r\n", "\n"), POSIX), outer_sep))


def posix_statements(cmd: str) -> Tuple[Tuple[Tuple[str, str, str], ...], ...]:
    """The units of `cmd` grouped by STATEMENT: a top-level command with its
    own $( ) substitutions, nested -c payloads and heredoc bodies, and the
    commands a `|` or `|&` joins to it. posix_units flattens exactly these.

    For questions that belong to a statement rather than a unit - which
    database does `echo "DELETE ..." | sqlite3 app.db` write? The SQL is in
    one unit and the database in the next, and only the pipe connects them.
    """
    script = parse(cmd.replace("\r\n", "\n"), POSIX)
    groups: List[Tuple[Tuple[str, str, str], ...]] = []
    cur: List[Command] = []
    for cm in script.commands:
        cur.append(cm)
        if cm.sep not in ("|", "|&"):
            groups.append(tuple((t, d, sp) for t, d, sp, _f in
                                _units(Script(script.line, cur))))
            cur = []
    if cur:
        groups.append(tuple((t, d, sp) for t, d, sp, _f in
                            _units(Script(script.line, cur))))
    return tuple(groups)
