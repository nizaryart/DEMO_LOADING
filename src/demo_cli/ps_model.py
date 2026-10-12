"""PowerShell, parsed once - the second front end's reader (C3, ruling PS1).

`model.py` does this for POSIX. This file is its PowerShell counterpart, and
it exists for the same reason: a regular expression reads CHARACTERS, while
PowerShell BINDS PARAMETERS. `Set-Content a.txt hi` writes a.txt because
a.txt binds to -Path at position 0 and `hi` to -Value at position 1 - not
because the text looks like a write. Only a parser that keeps the structure
can hand the binder (engine/ps_bind.py) something to bind.

WHY OUR OWN PARSER AND NOT PowerShell's (ruling PS1)
PowerShell can parse a line for us - `[Parser]::ParseInput` - but starting
powershell.exe costs hundreds of milliseconds on the hook's hot path, and the
guard must also answer from WSL, where there may be no PowerShell at all. So
the reading is ours, and PowerShell's own parser is used where it belongs: as
an ORACLE in the tests (tests/test_c3_oracle.py compares the two on a corpus
of real agent lines).

WHAT IT REFUSES TO GUESS
Every construct outside the grammar below leaves a reason in
`PsScript.not_understood`, and the engine turns that into "not understood" -
the runtime net, else a checkpoint, else escalate. A parser that silently
dropped what it could not read would be worse than no parser: it would
produce a confident, wrong answer. The known gaps are deliberate and listed
in `PsScript.not_understood` by name: classes, functions, param() blocks,
try/catch, switch, splatting (@args), the stop-parsing token (--%), and any
string built at run time.

WHAT IT MODELS
  * quoting: 'literal' (no expansion) vs "expandable" ($x, $(...) inside),
    the backtick escape, and the backtick line continuation;
  * here-strings @'...'@ (literal) and @"..."@ (expandable);
  * pipelines |, statement separators ; and newlines, && and || (5.1 parses
    them as errors; 7+ accepts them - both are recorded, never guessed);
  * sub-expressions $( ) and @( ) as NESTED SCRIPTS, like model.py does for
    $( ) - what runs inside runs, and its effects count;
  * script blocks { } kept whole, so ForEach-Object { Remove-Item $_ } can be
    analysed where it runs;
  * the call operator &, redirections (> >> 2> 2>&1 *>), $env: variables and
    same-line assignments;
  * parameters in all three spellings PowerShell accepts: -Name, -Name:value
    and -Name value, left for the binder to resolve - the parser only says
    which is which.

Windows-only in subject, not in execution: this file is pure Python and is
tested on Linux, exactly like fsguard.py.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# A parameter is a dash followed by a name: -Recurse, -Path, -Force.
# PowerShell accepts the en dash and em dash as well (a paste from a document
# keeps working), which is why this is not simply "-".
DASHES = "-\u2013\u2014\u2015"

# What ends a bareword. Note that `-` is NOT here: file-name.txt is one word.
_SPECIAL = set(" \t\r\n|;&(){}'\"#,")

# The redirection operators of PowerShell 5.1, longest first so that `2>&1`
# is never read as `2>` followed by `&1`.
_REDIRECTS = ("2>&1", "*>&1", "3>&1", "4>&1", "5>&1", "6>&1",
              "*>>", "2>>", "*>", "2>", ">>", ">", "<")

# Statement separators and the operators that join pipelines.
_JOINERS = ("&&", "||")


@dataclass
class PsWord:
    """One argument, parameter or command name, with its source text.

    `value` is the text with quotes removed and nothing expanded; `expands`
    says the value is NOT static - a variable, a sub-expression, a double
    quoted string holding either. The binder may bind an expanding word to a
    parameter, but the simulation must not treat its value as a path.
    """
    raw: str
    value: str
    start: int
    end: int
    kind: str = "bare"          # bare | single | double | here | variable | sub | block | param
    expands: bool = False
    nested: Optional["PsScript"] = None     # $( ) @( ) { }: what runs inside
    param_name: Optional[str] = None        # kind == "param": the name after the dash
    param_value: Optional["PsWord"] = None  # -Name:value, the attached value
    elements: Optional[List["PsWord"]] = None   # an array literal: a.txt, b.txt

    @property
    def is_param(self) -> bool:
        return self.kind == "param"

    @property
    def values(self) -> List["PsWord"]:
        """Every value this word carries: an array's elements, or itself.

        `Remove-Item a.txt, b.txt` deletes BOTH - PowerShell binds the comma
        list as one array to -Path. Reading only the first would under-report
        a deletion, which is the kind of mistake this engine exists to avoid.
        """
        return list(self.elements) if self.elements else [self]


@dataclass
class PsRedirect:
    op: str
    target: Optional[PsWord]
    start: int


@dataclass
class PsCommand:
    """One element of a pipeline.

    Usually a command: a name and the words that follow it. It may instead be
    an EXPRESSION - `"a.txt" | Remove-Item` and `@'...'@ | Set-Content` start
    with a value, not a command, and that value is what flows down the pipe.
    Reading it as a command named `a.txt` would both invent a command and lose
    the operand the next cmdlet binds (`is_expression` is what tells them
    apart).
    """
    words: List[PsWord] = field(default_factory=list)
    redirects: List[PsRedirect] = field(default_factory=list)
    amp: bool = False                # started with the call operator &
    is_expression: bool = False      # a value, not a command (see above)
    line: str = ""

    @property
    def name(self) -> str:
        return "" if self.is_expression else (self.words[0].value if self.words else "")

    @property
    def value(self) -> Optional[PsWord]:
        """The value an expression element puts on the pipeline, if static."""
        if self.is_expression and self.words:
            return self.words[0]
        return None

    @property
    def args(self) -> List[PsWord]:
        return self.words[1:]

    @property
    def text(self) -> str:
        if not self.words:
            return ""
        a = self.words[0].start
        b = max([w.end for w in self.words]
                + [r.target.end for r in self.redirects if r.target])
        return self.line[a:b].strip()


@dataclass
class PsPipeline:
    """Commands joined by `|`. The first one feeds the second, and so on."""
    commands: List[PsCommand] = field(default_factory=list)
    joiner: str = ""                 # what SEPARATED it from the next: ; && || or ""


@dataclass
class PsAssign:
    """`$x = <something>`: the variable, and the words it is set from."""
    name: str
    words: List[PsWord] = field(default_factory=list)


@dataclass
class PsScript:
    line: str
    pipelines: List[PsPipeline] = field(default_factory=list)
    assigns: List[PsAssign] = field(default_factory=list)
    not_understood: List[Tuple[str, str]] = field(default_factory=list)

    def cannot_read(self, unit: str, why: str) -> None:
        item = (unit[:120], why)
        if item not in self.not_understood:
            self.not_understood.append(item)


# --------------------------------------------------------------------------
# Lexer
#
# PowerShell's quoting is not POSIX's, and the differences are exactly where a
# text rule goes wrong:
#   'a$b'      literal: $b is two characters, not a variable
#   "a$b"      expandable: $b is a variable
#   `          the escape AND the line continuation (POSIX uses \)
#   ''         inside a single-quoted string, an escaped quote
#   ""         inside a double-quoted string, an escaped quote
# --------------------------------------------------------------------------

_ESCAPES = {"0": "\0", "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r",
            "t": "\t", "v": "\v", "`": "`", "'": "'", '"': '"', "$": "$"}


class _Lexer:
    def __init__(self, text: str, script: PsScript) -> None:
        self.s = text
        self.i = 0
        self.n = len(text)
        self.script = script

    # -- helpers ----------------------------------------------------------
    def peek(self, k: int = 0) -> str:
        j = self.i + k
        return self.s[j] if j < self.n else ""

    def starts(self, lit: str) -> bool:
        return self.s.startswith(lit, self.i)

    def skip_blanks(self) -> None:
        """Spaces, tabs, comments, and the backtick line continuation."""
        while self.i < self.n:
            c = self.s[self.i]
            if c in " \t":
                self.i += 1
            elif c == "`" and self.peek(1) in ("\n", "\r"):
                self.i += 2
                if self.s[self.i - 1:self.i + 1] == "\r\n":
                    self.i += 1
            elif c == "#":
                while self.i < self.n and self.s[self.i] not in "\r\n":
                    self.i += 1
            elif self.starts("<#"):
                end = self.s.find("#>", self.i + 2)
                self.i = self.n if end < 0 else end + 2
            else:
                return

    # -- strings ----------------------------------------------------------
    def single_quoted(self) -> PsWord:
        """'literal': nothing expands, '' is one quote."""
        start = self.i
        self.i += 1
        out = []
        while self.i < self.n:
            c = self.s[self.i]
            if c == "'":
                if self.peek(1) == "'":
                    out.append("'")
                    self.i += 2
                    continue
                self.i += 1
                return PsWord(self.s[start:self.i], "".join(out), start, self.i, "single")
            out.append(c)
            self.i += 1
        self.script.cannot_read(self.s[start:], "a quote that is never closed")
        return PsWord(self.s[start:], "".join(out), start, self.n, "single", expands=True)

    def double_quoted(self) -> PsWord:
        """"expandable": $x, $env:X and $( ) inside; `` escapes; "" is one quote."""
        start = self.i
        self.i += 1
        out: List[str] = []
        expands = False
        nested: List[PsScript] = []
        while self.i < self.n:
            c = self.s[self.i]
            if c == '"':
                if self.peek(1) == '"':
                    out.append('"')
                    self.i += 2
                    continue
                self.i += 1
                w = PsWord(self.s[start:self.i], "".join(out), start, self.i, "double",
                           expands=expands)
                if nested:
                    w.nested = nested[0] if len(nested) == 1 else _merge(nested)
                return w
            if c == "`" and self.i + 1 < self.n:
                out.append(_ESCAPES.get(self.s[self.i + 1], self.s[self.i + 1]))
                self.i += 2
                continue
            if c == "$" and self.peek(1) == "(":
                inner, sub = self.sub_expression()
                nested.append(sub)
                expands = True
                out.append(inner)
                continue
            if c == "$":
                name = self.variable_name()
                expands = True
                out.append("$" + name)
                continue
            out.append(c)
            self.i += 1
        self.script.cannot_read(self.s[start:], "a quote that is never closed")
        return PsWord(self.s[start:], "".join(out), start, self.n, "double", expands=True)

    def here_string(self) -> PsWord:
        """@'...'@ (literal) and @"..."@ (expandable). The terminator must sit
        at the start of its own line - that is what makes a here-string able to
        hold quotes and dollars unharmed."""
        start = self.i
        quote = self.peek(1)
        end_mark = "\n" + quote + "@"
        j = self.s.find(end_mark, self.i + 2)
        if j < 0:
            self.script.cannot_read(self.s[start:start + 60], "a here-string that is never closed")
            self.i = self.n
            return PsWord(self.s[start:], "", start, self.n, "here", expands=True)
        body_start = self.s.find("\n", self.i + 2)
        body = self.s[body_start + 1:j] if 0 <= body_start < j else ""
        self.i = j + len(end_mark)
        expands = quote == '"' and ("$" in body)
        return PsWord(self.s[start:self.i], body, start, self.i, "here", expands=expands)

    # -- $( ) and ${ } ----------------------------------------------------
    def balanced(self, open_c: str, close_c: str) -> Tuple[int, int]:
        """The span INSIDE a balanced pair, quotes respected. The cursor is on
        the opening character; it ends just past the closing one."""
        depth = 0
        begin = self.i
        while self.i < self.n:
            c = self.s[self.i]
            if c == "'":
                self.single_quoted()
                continue
            if c == '"':
                self.double_quoted()
                continue
            if c == "`":
                self.i += 2
                continue
            if c == open_c:
                depth += 1
            elif c == close_c:
                depth -= 1
                self.i += 1
                if depth == 0:
                    return begin, self.i
                continue
            self.i += 1
        self.script.cannot_read(self.s[begin:begin + 60], f"a {open_c}{close_c} that is never closed")
        return begin, self.n

    def sub_expression(self) -> Tuple[str, PsScript]:
        """$( ) or @( ): what is inside RUNS, so it is parsed as a script."""
        self.i += 1                                  # past the $ or @
        a, b = self.balanced("(", ")")
        inner = self.s[a + 1:b - 1]
        return self.s[a - 1:b], parse(inner)

    def variable_name(self) -> str:
        """$x, ${x y}, $env:PATH, $global:x - the name only, cursor past it."""
        self.i += 1                                  # past the $
        if self.peek() == "{":
            a, b = self.balanced("{", "}")
            return self.s[a + 1:b - 1]
        start = self.i
        while self.i < self.n and (self.s[self.i].isalnum() or self.s[self.i] in "_:?^"):
            self.i += 1
        return self.s[start:self.i]

    # -- one word ---------------------------------------------------------
    def word(self) -> Optional[PsWord]:
        self.skip_blanks()
        if self.i >= self.n:
            return None
        c = self.s[self.i]
        start = self.i

        if c == "@" and self.peek(1) in ("'", '"'):
            return self.here_string()
        if c == "@" and self.peek(1) == "(":
            raw, inner = self.sub_expression()
            return PsWord(raw, "", start, self.i, "sub", expands=True, nested=inner)
        if c == "@":                                  # splatting: @args, @params
            while self.i < self.n and self.s[self.i] not in _SPECIAL:
                self.i += 1
            raw = self.s[start:self.i]
            self.script.cannot_read(raw, "splatting: the arguments come from a variable")
            return PsWord(raw, "", start, self.i, "bare", expands=True)
        if c == "$" and self.peek(1) == "(":
            raw, inner = self.sub_expression()
            return PsWord(raw, "", start, self.i, "sub", expands=True, nested=inner)
        if c == "{":
            a, b = self.balanced("{", "}")
            inner = self.s[a + 1:b - 1]
            return PsWord(self.s[a:b], inner, start, self.i, "block", expands=True,
                          nested=parse(inner))
        if c == "(":
            a, b = self.balanced("(", ")")
            inner = self.s[a + 1:b - 1]
            return PsWord(self.s[a:b], "", start, self.i, "sub", expands=True,
                          nested=parse(inner))
        if c in DASHES and (self.peek(1).isalpha() or self.peek(1) == "-"):
            return self.parameter()

        # One word, read as the pieces glued together that PowerShell reads:
        #   C:\logs\$name.txt    $env:APPDATA\notes.txt    'a'.txt    file-name.txt
        # A word of ONE piece keeps that piece's kind ('x' is a literal string,
        # $x is a variable), which is how a pipeline element that is a VALUE is
        # told from one that is a command. Anything glued is a bareword.
        out: List[str] = []
        expands = False
        pieces: List[str] = []
        inner: List[PsScript] = []          # $( ) met inside, quoted or not
        while self.i < self.n:
            ch = self.s[self.i]
            if ch in _SPECIAL and ch not in "'\"":   # quotes are pieces, not ends
                break
            if ch in "<>" or self.s[self.i:self.i + 2] == "*>":
                break
            if ch == "`" and self.i + 1 < self.n:
                out.append(_ESCAPES.get(self.s[self.i + 1], self.s[self.i + 1]))
                self.i += 2
                pieces.append("bare")
                continue
            if ch == "$":
                if self.peek(1) == "(":
                    inner_raw, sub = self.sub_expression()
                    out.append(inner_raw)
                    inner.append(sub)
                    pieces.append("sub")
                else:
                    # Argument mode: `C:\logs\$name.txt` is the variable
                    # followed by the literal text `.txt`, NOT a member access
                    # - PowerShell only reads `$x.Prop` as a member in
                    # expression position. Whatever follows stays part of this
                    # word, and the word expands either way.
                    name = self.variable_name()
                    out.append("$" + name)
                    pieces.append("variable")
                expands = True
                continue
            if ch == "'":
                out.append(self.single_quoted().value)
                pieces.append("single")
                continue
            if ch == '"':
                w = self.double_quoted()
                out.append(w.value)
                expands = expands or w.expands
                if w.nested is not None:      # "$(Remove-Item x)": it still runs
                    inner.append(w.nested)
                pieces.append("double")
                continue
            out.append(ch)
            self.i += 1
            pieces.append("bare")
        raw = self.s[start:self.i]
        if not raw:                                   # a lone special character
            self.i += 1
            raw = self.s[start:self.i]
        kind = "bare"
        if pieces and all(p == pieces[0] for p in pieces) and pieces[0] != "bare":
            kind = pieces[0]
        word = PsWord(raw, "".join(out), start, self.i, kind, expands=expands)
        if inner:
            word.nested = inner[0] if len(inner) == 1 else _merge(inner)
            if kind == "bare":
                kind = word.kind = "double"   # it carries code, like a quoted one
        return word

    def parameter(self) -> PsWord:
        """-Name, -Name:value, --% . The binder decides what -Name means; the
        parser only separates the name from an attached value."""
        start = self.i
        if self.starts("--%"):
            self.i = self.n                           # everything after is passed verbatim
            raw = self.s[start:]
            self.script.cannot_read(raw, "--%: the rest of the line is not parsed by PowerShell")
            return PsWord(raw, raw, start, self.n, "bare", expands=True)
        self.i += 1
        if self.peek() in DASHES:
            self.i += 1                               # --version binds to -version
        name_start = self.i
        while self.i < self.n and (self.s[self.i].isalnum() or self.s[self.i] == "_"):
            self.i += 1
        name = self.s[name_start:self.i]
        attached: Optional[PsWord] = None
        if self.peek() == ":":
            self.i += 1
            attached = self.word()
        return PsWord(self.s[start:self.i], name, start, self.i, "param",
                      param_name=name, param_value=attached)


def _merge(scripts: List[PsScript]) -> PsScript:
    """Several $( ) in one string: one script holding all their pipelines."""
    out = PsScript(" ".join(s.line for s in scripts))
    for s in scripts:
        out.pipelines.extend(s.pipelines)
        out.assigns.extend(s.assigns)
        out.not_understood.extend(s.not_understood)
    return out


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

# Keywords whose bodies C3 does not read. Each one leaves a reason, so the
# line goes to the runtime net rather than being judged on what we did read.
_UNREAD_KEYWORDS = {
    "function": "a function definition: its body runs later, under its own name",
    "filter": "a filter definition: its body runs later",
    "workflow": "a workflow definition",
    "class": "a class definition",
    "enum": "an enum definition",
    "param": "a param() block",
    "begin": "a begin/process/end block",
    "process": "a begin/process/end block",
    "end": "a begin/process/end block",
    "switch": "a switch statement",
    "trap": "a trap: code registered to run on an error",
    "try": "try/catch: which branch runs is not known",
    "catch": "try/catch: which branch runs is not known",
    "finally": "try/catch/finally",
    "data": "a data section",
    "configuration": "a DSC configuration",
}

# Keywords C3 reads THROUGH: what follows is ordinary commands, and the
# condition or the loop header does not itself touch files. `if` and the
# loops are modelled as "the body may run", which is the stricter reading.
_PASS_KEYWORDS = {"if", "elseif", "else", "foreach", "for", "while", "do", "until"}


def parse(line: str, _depth: int = 0) -> PsScript:
    """Read one PowerShell line (or script) into pipelines of commands.

    Never raises: anything it cannot read becomes a reason in
    `script.not_understood`, which the engine turns into "not understood".
    """
    text = line.replace("\r\n", "\n")
    script = PsScript(text)
    if _depth > 8:
        script.cannot_read(text[:80], "nested too deep to follow")
        return script

    lex = _Lexer(text, script)
    pipeline = PsPipeline()
    command = PsCommand(line=text)

    # A pipeline element that STARTS with a value is an expression, not a
    # command: `"a.txt" | Remove-Item`, `@'..'@ | Set-Content`, `$p | ri`.
    _VALUE_KINDS = {"single", "double", "here", "variable", "sub"}

    def end_command() -> None:
        nonlocal command
        if command.words or command.redirects:
            if command.words and not command.amp:
                command.is_expression = command.words[0].kind in _VALUE_KINDS
            pipeline.commands.append(command)
        command = PsCommand(line=text)

    def end_pipeline(joiner: str = "") -> None:
        nonlocal pipeline
        end_command()
        if pipeline.commands:
            pipeline.joiner = joiner
            script.pipelines.append(pipeline)
        pipeline = PsPipeline()

    while True:
        lex.skip_blanks()
        if lex.i >= lex.n:
            break
        c = lex.peek()

        if c in "\n\r;":
            lex.i += 1
            end_pipeline(";")
            continue
        if c == "|":
            lex.i += 1
            end_command()
            continue
        if lex.starts("&&") or lex.starts("||"):
            joiner = text[lex.i:lex.i + 2]
            lex.i += 2
            end_pipeline(joiner)
            continue
        if c == "&" and not command.words:
            lex.i += 1
            command.amp = True
            continue
        if c == "&":                                  # a trailing & : run in background
            lex.i += 1
            script.cannot_read(command.text or text[:60],
                               "a background job: it outlives the command")
            continue

        redirect = _redirect_at(lex)
        if redirect is not None:
            command.redirects.append(redirect)
            continue

        word = lex.word()
        if word is None:
            break

        # An array literal: `a.txt, b.txt` is ONE argument holding two values
        # (PowerShell binds the whole list to one parameter).
        lex.skip_blanks()
        if lex.peek() == ",":
            elements = [word]
            while lex.peek() == ",":
                lex.i += 1
                nxt = lex.word()
                if nxt is None:
                    break
                elements.append(nxt)
                lex.skip_blanks()
            word = PsWord(text[word.start:elements[-1].end],
                          ",".join(e.value for e in elements),
                          word.start, elements[-1].end, "array",
                          expands=any(e.expands for e in elements), elements=elements)

        # An assignment: $x = ..., $env:X = ...
        if (not command.words and word.kind == "variable"
                and _next_is_equals(lex)):
            lex.skip_blanks()
            lex.i += 1                                # past the =
            values: List[PsWord] = []
            while True:
                lex.skip_blanks()
                if lex.i >= lex.n or lex.peek() in "\n\r;|":
                    break
                w = lex.word()
                if w is None:
                    break
                values.append(w)
                if w.nested is not None:              # $x = $(...) : it runs
                    script.pipelines.extend(w.nested.pipelines)
                    script.not_understood.extend(w.nested.not_understood)
            script.assigns.append(PsAssign(word.value.lstrip("$"), values))
            end_pipeline(";")
            continue

        if not command.words and word.kind == "bare":
            low = word.value.lower()
            if low in _UNREAD_KEYWORDS:
                script.cannot_read(text[word.start:word.start + 80], _UNREAD_KEYWORDS[low])
                return script
            if low in _PASS_KEYWORDS:
                # `if (cond) { body }`: the condition is read as a script (it
                # may call a command), and the body is read where it runs.
                continue

        command.words.append(word)

    end_pipeline()

    # Nested scripts found inside words: what runs inside a $( ) runs.
    for pipe in list(script.pipelines):
        for cmd in pipe.commands:
            for w in cmd.words:
                if w.nested is not None and w.kind == "sub":
                    script.not_understood.extend(w.nested.not_understood)
    return script


def _next_is_equals(lex: _Lexer) -> bool:
    j = lex.i
    while j < lex.n and lex.s[j] in " \t":
        j += 1
    return j < lex.n and lex.s[j] == "=" and lex.s[j:j + 2] not in ("==", "=~")


def _redirect_at(lex: _Lexer) -> Optional[PsRedirect]:
    for op in _REDIRECTS:
        if lex.starts(op):
            start = lex.i
            lex.i += len(op)
            if op.endswith("&1"):
                return PsRedirect(op, None, start)
            target = lex.word()
            return PsRedirect(op, target, start)
    return None


def commands_of(script: PsScript) -> List[PsCommand]:
    """Every command the script runs, nested sub-expressions included."""
    out: List[PsCommand] = []
    for pipe in script.pipelines:
        for cmd in pipe.commands:
            out.append(cmd)
            for w in cmd.words:
                if w.nested is not None:
                    out.extend(commands_of(w.nested))
    return out
