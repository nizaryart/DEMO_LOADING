"""Word expansion ON WORDS, the way bash does it - not text substitution.

`substitute_assignments` in classify.py rewrites the command TEXT, so it
cannot tell `rm '$X'` (a literal name) from `rm $X`, and it applied a prefix
assignment to its own command (`X=a rm $X` - bash expands $X before X=a
takes effect). Here each word is expanded from its raw source with its
quoting intact:

  * single quotes and $'..' are literal; double quotes allow $NAME but do
    not split or glob; a backslash quotes the next character;
  * $NAME / ${NAME} come from assignments made EARLIER on the same line;
    anything else - $( ), `..`, $((..)), ${X:-..}, $1, $@, an unset name -
    is UNKNOWN, with the reason. Nothing is guessed;
  * a field the tool would read as an option (a value or a glob hit that starts with '-') is UNKNOWN (I1a);
  * an unquoted expansion is split on whitespace;
  * a leading unquoted ~ is the home directory;
  * braces, then globs, on unquoted text only. Globs see the real
    filesystem as the simulation has changed it so far.
"""
from __future__ import annotations

import glob as _glob
import os
import re
from typing import Callable, Dict, List, Optional, Tuple

from ..model import Word, ansi_c
from ..targets import _expand_braces

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_GLOB = "*?["
_IFS_WS = (" ", "\t", "\n")                    # bash's default IFS: nothing else splits
_IFS_SPLIT = re.compile(r"[ \t\n]+")

Chars = List[Tuple[str, bool]]          # (character, quoted?)


class Unknown(Exception):
    """This word cannot be resolved before it runs; `args[0]` says why."""


def expand(word: Word, vars_: Dict[str, Optional[str]], cwd: Optional[str],
           globber: Callable[[str], List[str]], plain: bool = False,
           outputs: Optional[Dict[str, Tuple[bool, str]]] = None) -> List[str]:
    """The fields `word` becomes. Globbed fields are absolute paths; the rest
    are as written, for the caller to resolve. Raises Unknown.

    `plain`: no splitting, braces or globs - how bash treats an assignment's
    value and how the command word is read here."""
    raw = word.raw
    if not word.expands and not any(c in raw for c in "~{*?[\\'\"$`"):
        return [word.value]
    fields: List[Chars] = [[]]
    i, n = 0, len(raw)

    def lit(ch: str, quoted: bool) -> None:
        fields[-1].append((ch, quoted))

    def emit(value: str, quoted: bool) -> None:
        if quoted or plain:
            for ch in value:
                lit(ch, True)
            return
        if "IFS" in vars_:
            raise Unknown("IFS is changed on this line")
        parts = [p for p in _IFS_SPLIT.split(value) if p]
        if value[:1] in _IFS_WS and fields[-1]:
            fields.append([])
        for k, part in enumerate(parts):
            if k:
                fields.append([])
            for ch in part:
                lit(ch, False)
        if value[-1:] in _IFS_WS and parts:
            fields.append([])

    def param(i: int, quoted: bool) -> int:
        """Expand the $... starting at raw[i] ('$'); returns the next index."""
        nxt = raw[i + 1] if i + 1 < n else ""
        if nxt == "(":
            if raw.startswith("$((", i):
                raise Unknown("arithmetic expansion")
            value, end = _substituted(word, i + 2, outputs, backtick=False)
            emit(value, quoted)
            return end
        if nxt == "{":
            j = raw.find("}", i + 2)
            inner = raw[i + 2:j] if j != -1 else ""
            if j == -1 or not _NAME.fullmatch(inner):
                raise Unknown(f"parameter expansion ${{{inner}}}")
            name, end = inner, j + 1
        else:
            m = _NAME.match(raw, i + 1)
            if not m:
                if nxt and nxt in "0123456789@*#?$!-":
                    raise Unknown(f"special parameter ${nxt}")
                lit("$", quoted)
                return i + 1
            name, end = m.group(0), m.end()
        emit(_lookup(name, vars_, cwd), quoted)
        return end

    while i < n:
        ch = raw[i]
        if ch == "\\":
            if i + 1 < n:
                lit(raw[i + 1], True)
            i += 2
        elif ch == "'":
            j = raw.find("'", i + 1)
            j = n if j == -1 else j
            for c in raw[i + 1:j]:
                lit(c, True)
            i = j + 1
        elif ch == "$" and raw.startswith("$'", i):
            j = i + 2
            while j < n and raw[j] != "'":
                j += 2 if raw[j] == "\\" else 1
            decoded = ansi_c(raw[i + 2:j])
            if decoded is None:
                raise Unknown("an ANSI-C escape this engine does not decode")
            for c in decoded:
                lit(c, True)
            i = j + 1
        elif ch == '"':
            i += 1
            while i < n and raw[i] != '"':
                c = raw[i]
                if c == "\\" and i + 1 < n and raw[i + 1] in '$`"\\\n':
                    lit(raw[i + 1], True)
                    i += 2
                elif c == "$":
                    i = param(i, True)
                elif c == "`":
                    value, i = _substituted(word, i + 1, outputs, backtick=True)
                    emit(value, True)
                else:
                    lit(c, True)
                    i += 1
            i += 1
        elif ch == "$":
            i = param(i, False)
        elif ch == "`":
            value, i = _substituted(word, i + 1, outputs, backtick=True)
            emit(value, False)
        elif ch in "<>" and raw.startswith("(", i + 1):
            raise Unknown("process substitution")
        elif ch == "~" and i == 0 and (n == 1 or raw[1] == "/"):
            for c in os.path.expanduser("~"):
                lit(c, True)
            i += 1
        else:
            lit(ch, False)
            i += 1

    if plain:
        return ["".join(c for chars in fields for c, _q in chars)]
    out: List[str] = []
    for chars in fields:
        if not chars:
            continue
        # Braces: bash expands them first, on unquoted text. Only a word with
        # no quoting and no expansion is brace-expanded here - the common
        # `rm file{1,2}.txt`; anything subtler keeps its braces literally.
        texts = ([ "".join(c for c, _q in chars) ]
                 if any(q for _c, q in chars) or "{" not in raw or "$" in raw
                 else _expand_braces("".join(c for c, _q in chars)))
        for text in texts:
            if len(texts) > 1 or not any(q for _c, q in chars):
                pattern_chars = [(c, False) for c in text]
            else:
                pattern_chars = chars
            if any(c in _GLOB and not q for c, q in pattern_chars):
                pattern = "".join(_glob.escape(c) if q else c for c, q in pattern_chars)
                if cwd is None and not os.path.isabs(pattern):
                    raise Unknown("a glob in an unknown working directory")
                base = pattern if os.path.isabs(pattern) else os.path.join(cwd or "", pattern)
                hits = globber(base)
                if (hits and not os.path.isabs(pattern)
                        and pattern_chars[0][0] in _GLOB and not pattern_chars[0][1]
                        and any(os.path.relpath(h, cwd).startswith("-") for h in hits)):
                    # I1a (msg 049): `rm *` hands a file named -rf to rm as `-rf`.
                    # Only a pattern that STARTS with a glob character can make a
                    # field that starts with '-': `./*` gives ./-rf, a file name.
                    raise Unknown("a file name that starts with '-' would be read as an option")
                out.extend(hits if hits else [text])       # no match: literal, as bash
            else:
                out.append(text)
    return out


def _substituted(word: Word, at: int, outputs, backtick: bool) -> Tuple[str, int]:
    for a, b, inner in word.subs:
        if a == word.start + at:
            if outputs is None or inner not in outputs or (backtick and "\\" in inner):
                raise Unknown("command substitution")
            ok, text = outputs[inner]
            if not ok:
                raise Unknown(f"command substitution: {text}")
            return text, b - word.start + 1
    raise Unknown("command substitution")


def _lookup(name: str, vars_: Dict[str, Optional[str]], cwd: Optional[str]) -> str:
    if name in vars_:
        value = vars_[name]
        if value is None:
            raise Unknown(f"${name} has a value this line does not show")
        return value
    if name == "HOME":
        return os.path.expanduser("~")
    if name == "PWD" and cwd is not None:
        return cwd
    raise Unknown(f"${name} is not set on this line")
