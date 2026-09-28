"""The rule table, as data: which tool does what, with its own examples.

A rule is keyed by tool name (the command word's basename). It carries the
tool's option grammar, a condition on the parsed flags, the effects it
produces, and example commands. The examples are not documentation: every
one becomes a test (tests/test_engine_rules.py) that runs the whole pipeline
in a fixed fixture tree and checks the impact.

Part B holds the first families only: rm / rmdir / unlink, and the output
redirections every command can carry. A tool with no rule has no effect -
today's behaviour - and is reported as `uncovered`, so "safe" and "not
understood yet" stay apart. Everything else arrives in Part C.

Example paths are relative to the fixture root; a trailing "/" marks a
directory. The fixture (tests/test_engine_rules.py, FIXTURE) holds:
    a.txt  b.txt  -f  dir/d.txt  dir/e.txt  emptydir/  sub/c.txt  list.txt
"""
from __future__ import annotations

from typing import Dict, FrozenSet, List, Mapping, Optional, Tuple

from .effects import CREATE, DELETE, MOVE


class OptionSpec:
    """A tool's option grammar. `flags` and `values` map every spelling to
    a canonical name; `values` are the options that take an argument."""
    __slots__ = ("flags", "values", "permute")

    def __init__(self, flags: Optional[Mapping[str, str]] = None,
                 values: Optional[Mapping[str, str]] = None, permute: bool = True):
        self.flags = dict(flags or {})
        self.values = dict(values or {})
        self.permute = permute                  # GNU: options may follow operands


class EffectT:
    """An effect template: applied to the rule's operands at simulation."""
    __slots__ = ("kind", "recursive_if", "dir_if", "dirs_only", "files_only")

    def __init__(self, kind: str, recursive_if: Optional[str] = None,
                 dir_if: Optional[str] = None, dirs_only: bool = False,
                 files_only: bool = False):
        self.kind = kind
        self.recursive_if = recursive_if        # canonical flag making a DELETE recursive
        self.dir_if = dir_if                    # canonical flag letting it remove an EMPTY dir
        self.dirs_only = dirs_only              # rmdir: directories only, and only empty ones
        self.files_only = files_only            # unlink: never a directory


class Example:
    __slots__ = ("command", "destroys", "creates", "changes", "unknown", "note")

    def __init__(self, command: str, destroys=frozenset(), creates=frozenset(),
                 changes=frozenset(), unknown: bool = False, note: str = ""):
        self.command, self.destroys, self.creates = command, destroys, creates
        self.changes, self.unknown, self.note = changes, unknown, note


def ex(command: str, destroys=(), creates=(), changes=(), unknown=False, note="") -> Example:
    return Example(command, frozenset(destroys), frozenset(creates), frozenset(changes),
                   unknown, note)


class Rule:
    __slots__ = ("id", "tools", "options", "effects", "when", "examples")

    def __init__(self, id: str, tools: Tuple[str, ...], options: OptionSpec,
                 effects: Tuple[EffectT, ...], when: Optional[Mapping] = None,
                 examples: Tuple[Example, ...] = ()):
        self.id, self.tools, self.options, self.effects = id, tools, options, effects
        # {"flags_all": [...], "flags_any": [...], "flags_none": [...],
        #  "flags_none_before_operands": [...]}
        self.when = dict(when or {})
        self.examples = examples


_HELP = {"--help": "help", "--version": "version"}

RULES: Tuple[Rule, ...] = (
    Rule(
        id="rm",
        tools=("rm",),
        options=OptionSpec(flags={
            "-f": "force", "--force": "force",
            "-r": "recursive", "-R": "recursive", "--recursive": "recursive",
            "-d": "dir", "--dir": "dir",
            "-i": "prompt", "-I": "prompt", "--interactive": "prompt",
            "-v": "verbose", "--verbose": "verbose",
            "--one-file-system": "one_fs",
            "--preserve-root": "preserve_root", "--no-preserve-root": "no_preserve_root",
            **_HELP}),
        effects=(EffectT(DELETE, recursive_if="recursive", dir_if="dir"),),
        when={"flags_none_before_operands": ("help", "version")},
        examples=(
            ex("rm a.txt", destroys={"a.txt"}),
            ex("\\rm -f a.txt b.txt > log.txt", destroys={"a.txt", "b.txt"},
               creates={"log.txt"}, note="the architecture page's trace"),
            ex("rm -rf dir", destroys={"dir/"}),
            ex("rm dir", note="no -r: rm refuses a directory"),
            ex("rm -d emptydir", destroys={"emptydir/"}),
            ex("rm -d dir", note="-d removes only an EMPTY directory"),
            ex("rm -- -f", destroys={"-f"}, note="after --, -f is a file"),
            ex("rm a.txt -f", destroys={"a.txt"}, note="GNU: options after operands"),
            ex("rm -f missing.txt", note="absent: nothing is lost"),
            ex("rm --help", note="prints help, removes nothing"),
            ex("rm -rf dir --help", destroys={"dir/"},
               note="after an operand --help is not trusted: BSD rm deletes dir"),
            ex("sudo rm -r sub", destroys={"sub/"}),
            ex("rm dir/*.txt", destroys={"dir/d.txt", "dir/e.txt"}),
            ex("rm {a,b}.txt", destroys={"a.txt", "b.txt"}),
            ex('rm "dir/*.txt"', note="quoted: a literal name, which does not exist"),
            ex("X=a.txt; rm $X", destroys={"a.txt"}),
            ex("X=a.txt rm $X", unknown=True,
               note="a prefix assignment does not feed its own command: $X is "
                    "whatever the shell already had, which the hook cannot see"),
            ex("rm '$X'", note="single quotes: a literal name"),
            ex("rm $(cat list.txt)", unknown=True),
            ex("cat list.txt | xargs rm", unknown=True, note="operands come from stdin"),
            ex('echo "rm -rf dir"', note="text, not a command"),
            ex("# rm -rf dir", note="a comment"),
            ex("cd dir && rm d.txt", destroys={"dir/d.txt"}),
            ex("cd missing; rm a.txt", destroys={"a.txt"},
               note="cd fails, the rm runs where we are"),
            ex("(cd dir; rm d.txt); rm a.txt", destroys={"dir/d.txt", "a.txt"},
               note="the subshell's cd does not leak"),
            ex("bash -c 'rm a.txt'", destroys={"a.txt"}),
            ex('echo "$(rm a.txt)"', destroys={"a.txt"}),
            ex("bash <<EOF\nrm a.txt\nEOF", destroys={"a.txt"}),
            ex("cat <<'EOF'\nrm a.txt\nEOF", note="a heredoc read as data"),
        ),
    ),
    Rule(
        id="rmdir",
        tools=("rmdir",),
        options=OptionSpec(flags={
            "-p": "parents", "--parents": "parents", "-v": "verbose", "--verbose": "verbose",
            "--ignore-fail-on-non-empty": "ignore_nonempty", **_HELP}),
        effects=(EffectT(DELETE, dirs_only=True),),
        when={"flags_none_before_operands": ("help", "version")},
        examples=(
            ex("rmdir emptydir", destroys={"emptydir/"}),
            ex("rmdir dir", note="not empty: rmdir fails"),
            ex("rmdir a.txt", note="not a directory: rmdir fails"),
        ),
    ),
    Rule(
        id="unlink",
        tools=("unlink",),
        options=OptionSpec(flags=dict(_HELP)),
        effects=(EffectT(DELETE, files_only=True),),
        when={"flags_none_before_operands": ("help", "version")},
        examples=(
            ex("unlink a.txt", destroys={"a.txt"}),
            ex("unlink dir", note="unlink never removes a directory"),
        ),
    ),
)

# Output redirection applies to EVERY command, whatever the tool, so it is one
# rule outside the per-tool table: `> >| &> >&FILE` empty an existing file or
# create a new one; `>> &>>` append or create. /dev/* and fd duplications do
# nothing; a missing parent directory makes the redirection fail.
REDIRECT_EXAMPLES: Tuple[Example, ...] = (
    ex("echo x > a.txt", destroys={"a.txt"}),
    ex("echo x > new.txt", creates={"new.txt"}),
    ex("echo x >> a.txt", changes={"a.txt"}),
    ex("echo x >> new.txt", creates={"new.txt"}),
    ex("echo x >| a.txt", destroys={"a.txt"}),
    ex("ls &> out.log", creates={"out.log"}),
    ex("ls >& a.txt", destroys={"a.txt"}),
    ex("> a.txt echo hi", destroys={"a.txt"}, note="a redirect before the command word"),
    ex("ls 2>/dev/null", note="a sink, not a file"),
    ex("echo x 2>&1", note="an fd duplication"),
    ex("echo x > missingdir/f.txt", note="the parent does not exist: bash fails"),
    ex("echo x > $OUT", unknown=True),
)

# Tools that change nothing on their own (output redirection aside). Not
# `sort` (-o writes), `uniq` (a second operand is written), `tee`, `sed`,
# `find`, `awk`: those write, and belong to C.
READ_ONLY = frozenset({
    "echo", "printf", "cat", "ls", "grep", "egrep", "fgrep", "rg", "head", "tail",
    "wc", "cut", "tr", "true", "false", ":", "test", "[", "[[", "pwd", "which",
    "type", "date", "printenv", "stat", "file", "du", "df", "basename", "dirname",
    "realpath", "readlink", "id", "whoami", "uname", "hostname", "sleep", "seq",
    "less", "more", "diff", "cmp", "md5sum", "sha1sum", "sha256sum", "set", "shopt",
    "alias", "history", "jobs", "wait", "exit", "return", "shift", "trap", "umask",
})

SHELLS = frozenset({"bash", "sh", "dash", "zsh", "ksh"})


def rules_by_tool(rules: Tuple[Rule, ...] = RULES) -> Dict[str, List[Rule]]:
    table: Dict[str, List[Rule]] = {}
    for rule in rules:
        for tool in rule.tools:
            table.setdefault(tool, []).append(rule)
    return table


def applies(rule: Rule, parsed) -> bool:
    """`parsed` is invocation.Parsed. `flags_none_before_operands` is for
    --help / --version: GNU honours them anywhere, but a non-permuting rm
    (BSD, busybox) deletes `dir` in `rm -rf dir --help`, so after an operand
    they are not trusted to stop anything."""
    flags = parsed.flags
    when = rule.when or {}
    if any(f not in flags for f in when.get("flags_all", ())):
        return False
    if when.get("flags_any") and not any(f in flags for f in when["flags_any"]):
        return False
    if any(f in parsed.early_flags for f in when.get("flags_none_before_operands", ())):
        return False
    return not any(f in flags for f in when.get("flags_none", ()))


# A TEST-ONLY table for the simulation semantics (&&, ||, created-then-
# deleted, mv-then-rm). touch and mv belong to C; they are here so the
# semantics can be proven now without shipping those families early.
TEST_ONLY_RULES: Tuple[Rule, ...] = RULES + (
    Rule(id="touch", tools=("touch",), options=OptionSpec(flags={"-c": "no_create"}),
         effects=(EffectT(CREATE),), when={"flags_none": ("no_create",)}),
    Rule(id="mv", tools=("mv",), options=OptionSpec(flags={"-f": "force", "-n": "no_clobber"},
                                                    values={"-t": "target", "--target-directory": "target"}),
         effects=(EffectT(MOVE),), when={"flags_none": ("no_clobber",)}),
)
