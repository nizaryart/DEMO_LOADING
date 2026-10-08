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

from .effects import CREATE, DELETE, MKDIR, MOVE, OVERWRITE


class OptionSpec:
    """A tool's option grammar. `flags` and `values` map every spelling to
    a canonical name; `values` are the options that take an argument.
    `attached` are short options whose value can only be glued on (sed -i.bak,
    perl -pi.orig): the rest of the cluster is the value, possibly empty.
    Multi-letter short spellings (wget -nc) are matched whole, first.
    `arity`: canonical value options that take more than one word (sqlite3
    -lookaside SIZE N: VERIFIED, 2026-09-28)."""
    __slots__ = ("flags", "values", "attached", "permute", "arity")

    def __init__(self, flags: Optional[Mapping[str, str]] = None,
                 values: Optional[Mapping[str, str]] = None,
                 attached: Optional[Mapping[str, str]] = None, permute: bool = True,
                 arity: Optional[Mapping[str, int]] = None):
        self.flags = dict(flags or {})
        self.values = dict(values or {})
        self.attached = dict(attached or {})
        self.permute = permute                  # GNU: options may follow operands
        self.arity = dict(arity or {})


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
    __slots__ = ("command", "destroys", "creates", "changes", "unknown", "note",
                 "remote", "uncovered", "reaches", "databases", "no_capture",
                 "posix_only")

    def __init__(self, command: str, destroys=frozenset(), creates=frozenset(),
                 changes=frozenset(), unknown: bool = False, note: str = "",
                 remote: bool = False, uncovered=frozenset(), reaches=None,
                 databases=None, no_capture=frozenset(), posix_only: bool = False):
        self.command, self.destroys, self.creates = command, destroys, creates
        self.changes, self.unknown, self.note = changes, unknown, note
        self.remote, self.uncovered = remote or bool(reaches), uncovered
        self.reaches = dict(reaches) if reaches is not None else None   # label -> kind (C2)
        self.databases = dict(databases or {})                          # label -> kind (C2a)
        self.no_capture = frozenset(no_capture)                         # labels (C2a)
        self.posix_only = posix_only


def ex(command: str, destroys=(), creates=(), changes=(), unknown=False, note="",
       remote=False, uncovered=(), reaches=None, databases=None, no_capture=(),
       posix_only: bool = False) -> Example:
    return Example(command, frozenset(destroys), frozenset(creates), frozenset(changes),
                   unknown, note, remote, frozenset(uncovered), reaches, databases,
                   frozenset(no_capture), posix_only=posix_only)


class Rule:
    """`resolver` names a function in engine/resolvers.py for tools a template
    cannot express; the rule still holds their grammar and examples.
    `partial` ("network"): the file side is modelled, the rest is not yet.
    `verified` False: the grammar comes from documentation, not from the
    installed tool's --help (the tool was not installed where it was written)."""
    __slots__ = ("id", "tools", "options", "effects", "when", "examples",
                 "resolver", "partial", "verified")

    def __init__(self, id: str, tools: Tuple[str, ...], options: OptionSpec,
                 effects: Tuple[EffectT, ...] = (), when: Optional[Mapping] = None,
                 examples: Tuple[Example, ...] = (), resolver: Optional[str] = None,
                 partial: Optional[str] = None, verified: bool = True):
        self.id, self.tools, self.options, self.effects = id, tools, options, effects
        # {"flags_all": [...], "flags_any": [...], "flags_none": [...],
        #  "flags_none_before_operands": [...]}
        self.when = dict(when or {})
        self.examples = examples
        self.resolver, self.partial, self.verified = resolver, partial, verified


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
            ex("X=-rf; rm $X dir", unknown=True,
               note="the value is an option for rm, not a file name (I1a)"),
            ex("rm *", unknown=True,
               note="the fixture's file -f reaches rm as the option -f (I1a)"),
            ex("X=a.txt rm $X", unknown=True,
               note="a prefix assignment does not feed its own command: $X is "
                    "whatever the shell already had, which the hook cannot see"),
            ex("rm '$X'", note="single quotes: a literal name"),
            ex("rm $(cat list.txt)", destroys={"a.txt"},
               note="I1b: cat's output is read through the simulation"),
            ex("rm $(git ls-files -o)", unknown=True, note="git is not on the I1b list"),
            ex("cat list.txt | xargs rm", unknown=True, note="operands come from stdin"),
            ex('echo "rm -rf dir"', note="text, not a command"),
            ex("# rm -rf dir", note="a comment"),
            ex("cd dir && rm d.txt", destroys={"dir/d.txt"}),
            ex("cd missing; rm a.txt", destroys={"a.txt"},
               note="cd fails, the rm runs where we are"),
            ex("(cd dir; rm d.txt); rm a.txt", destroys={"dir/d.txt", "a.txt"},
               note="the subshell's cd does not leak"),
            ex("bash -c 'rm a.txt'", destroys={"a.txt"}),
            ex("demo_cli sh 'rm a.txt'", destroys={"a.txt"}),
            ex("python3 -m demo_cli run -- bash -c 'rm a.txt'", destroys={"a.txt"}),
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
    # review C1 fix 2: devices. A disk is a surface no local copy restores.
    ex("cat a.txt > /dev/sda", remote=True, note="a disk: ESCALATE (today: ALLOW)", posix_only=True),
    ex("echo x > /dev/stderr", note="a sink"),
    ex("echo x > /dev/fd/2", note="a sink"),
    ex("echo x > /dev/tty", note="a sink"),
    ex("echo x > /dev/null", note="a sink"),
    ex("echo x > /dev/zero", note="a sink"),
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
    # M2.2c: what a kill line reads its PIDs from (`kill $(lsof -ti:3000)`)
    "ps", "pgrep", "pidof", "lsof",
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


# ==========================================================================
# Part C, slice C1: local file tools (2026-09-27)
# ==========================================================================
from . import grammars as _g                                      # noqa: E402

_BACKUP = {"-b": "backup", "--backup": "backup"}
_DEST = {"-t": "target", "--target-directory": "target", "-S": "suffix", "--suffix": "suffix"}

TAR_OPTIONS = OptionSpec(flags=_g.TAR_FLAGS, values=_g.TAR_VALUES)

C1_RULES: Tuple[Rule, ...] = (
    Rule(id="cp", tools=("cp",), resolver="cp",
         options=OptionSpec(values={**_DEST, "--no-preserve": "no_preserve", "--sparse": "sparse"},
                            flags={
             **_BACKUP, **_HELP, "-r": "recursive", "-R": "recursive", "--recursive": "recursive",
             "-a": "recursive", "--archive": "recursive", "-n": "no_clobber",
             "--no-clobber": "no_clobber", "--update": "update", "-u": "update",
             "-T": "no_target_dir", "--no-target-directory": "no_target_dir",
             "-f": "force", "--force": "force", "-i": "prompt", "--interactive": "prompt",
             "-l": "link", "--link": "link", "-s": "symlink", "--symbolic-link": "symlink",
             "-L": "deref", "-H": "deref", "-P": "no_deref", "-d": "no_deref", "-p": "preserve",
             "--preserve": "preserve", "--parents": "parents",
             "--remove-destination": "remove_destination", "--attributes-only": "attributes_only",
             "--strip-trailing-slashes": "strip", "--reflink": "reflink",
             "-x": "one_fs", "--one-file-system": "one_fs", "-v": "verbose", "--verbose": "verbose",
             "--context": "context", "-Z": "context", "--debug": "debug",
             "--copy-contents": "copy_contents", "--keep-directory-symlink": "keep_symlink"}),
         when={"flags_none_before_operands": ("help", "version")},
         examples=(
             ex("cp a.txt b.txt", destroys={"b.txt"}),
             ex("cp a.txt new.txt", creates={"new.txt"}),
             ex("cp -n a.txt b.txt", note="-n never overwrites (VERIFIED)"),
             ex("cp --update=none a.txt b.txt", note="--update=none is -n"),
             ex("cp -b a.txt b.txt", destroys={"b.txt"}, creates={"b.txt~"},
                note="VERIFIED: the old b.txt is kept as b.txt~ - review C1: the backup is the tool's, the file is still destroyed"),
             ex("cp -b a.txt x.txt", destroys={"x.txt", "x.txt~"},
                note="review fix 1: the backup write replaces an existing x.txt~"),
             ex("cp a.txt b.txt dir/", creates={"dir/a.txt", "dir/b.txt"}),
             ex("cp -t dir a.txt", creates={"dir/a.txt"}),
             ex("cp a.txt", note="one operand: cp fails"),
             ex("cp -T a.txt dir", note="a file cannot replace a directory"),
             ex("cp -r dir sub", creates={"sub/dir"}),
             ex("cp dir sub", note="no -r: cp skips a directory"),
             ex("cp a.txt newdir/", note="VERIFIED: a trailing slash on a missing name fails"),
             ex("cp a.txt b.txt/", note="VERIFIED: b.txt/ is not a directory: cp fails"),
             ex("cp -r dir newdir/", creates={"newdir"},
                note="VERIFIED: a directory source takes the name"),
             ex("cp a.txt b.txt && rm a.txt", destroys={"a.txt", "b.txt"}),
             ex("cp a.txt /dev/sda", remote=True, note="a device", posix_only=True),
             ex("cp --sparse always a.txt new.txt", creates={"new.txt"},
                note="--sparse takes the next word (the grammar test found it missing)"),
         )),
    Rule(id="mv", tools=("mv",), resolver="mv",
         options=OptionSpec(values=_DEST, flags={
             **_BACKUP, **_HELP, "-n": "no_clobber", "--no-clobber": "no_clobber",
             "--update": "update", "-u": "update", "-T": "no_target_dir",
             "--no-target-directory": "no_target_dir", "-f": "force", "--force": "force",
             "-i": "prompt", "--interactive": "prompt", "-v": "verbose", "--verbose": "verbose",
             "--strip-trailing-slashes": "strip", "-Z": "context", "--context": "context",
             "--exchange": "exchange", "--debug": "debug"}),
         when={"flags_none_before_operands": ("help", "version")},
         examples=(
             ex("mv a.txt b.txt", destroys={"b.txt"}),
             ex("mv a.txt new.txt", note="a move onto a free name destroys nothing"),
             ex("mv -n a.txt b.txt", note="-n never overwrites"),
             ex("mv -b a.txt b.txt", destroys={"b.txt"}, creates={"b.txt~"}, note="review C1: the backup is the tool's, the file is still destroyed"),
             ex("mv -b a.txt x.txt", destroys={"x.txt", "x.txt~"}, note="review fix 1"),
             ex("mv a.txt dir/", note="dir/a.txt does not exist yet"),
             ex("mv a.txt b.txt/", note="VERIFIED: b.txt/ is not a directory: mv fails"),
             ex("mv -t dir a.txt b.txt"),
             ex("mv a.txt b.txt && rm b.txt", destroys={"a.txt", "b.txt"}),
         )),
    Rule(id="ln", tools=("ln",), resolver="ln",
         options=OptionSpec(values=_DEST, flags={
             **_BACKUP, **_HELP, "-f": "force", "--force": "force", "-s": "symbolic",
             "--symbolic": "symbolic", "-n": "no_deref", "--no-dereference": "no_deref",
             "-T": "no_target_dir", "--no-target-directory": "no_target_dir",
             "-r": "relative", "--relative": "relative", "-i": "prompt", "--interactive": "prompt",
             "-L": "logical", "--logical": "logical", "-P": "physical", "--physical": "physical",
             "-v": "verbose", "--verbose": "verbose", "-d": "directory", "-F": "directory",
             "--directory": "directory"}),
         when={"flags_none_before_operands": ("help", "version")},
         examples=(
             ex("ln -s a.txt link", creates={"link"}),
             ex("ln -sf a.txt b.txt", destroys={"b.txt"}, note="VERIFIED: -f replaces a file"),
             ex("ln -s a.txt b.txt", note="no -f: ln fails (VERIFIED)"),
             ex("ln -sf a.txt b.txt/", note="VERIFIED: b.txt/ is not a directory: ln fails"),
             ex("ln -s a.txt newdir/", note="VERIFIED: ln never takes a slashed missing name"),
             ex("ln -sfb a.txt b.txt", destroys={"b.txt"}, creates={"b.txt~"}, note="review C1: the backup is the tool's, the file is still destroyed"),
             ex("ln -s a.txt dir/", creates={"dir/a.txt"}),
             ex("ln -s dir/d.txt", destroys=set(), creates={"d.txt"},
                note="one operand: a link of that name in the cwd"),
         )),
    Rule(id="install", tools=("install",), resolver="install",
         options=OptionSpec(values={**_DEST, "-m": "mode", "--mode": "mode", "-o": "owner",
                                    "--owner": "owner", "-g": "group", "--group": "group",
                                    "--strip-program": "strip_program"},
                            flags={**_BACKUP, **_HELP, "-c": "ignored", "-C": "compare",
                                   "--compare": "compare", "-d": "directory",
                                   "--directory": "directory", "-D": "create_leading",
                                   "-p": "preserve", "--preserve-timestamps": "preserve",
                                   "-s": "strip", "--strip": "strip", "-T": "no_target_dir",
                                   "--no-target-directory": "no_target_dir", "-v": "verbose",
                                   "--verbose": "verbose", "-Z": "context", "--context": "context",
                                   "--debug": "debug"}),
         when={"flags_none_before_operands": ("help", "version")},
         examples=(
             ex("install a.txt b.txt", destroys={"b.txt"}),
             ex("install -m 644 a.txt new.txt", creates={"new.txt"}),
             ex("install -d newdir", creates={"newdir"}),
             ex("install -b a.txt b.txt", destroys={"b.txt"}, creates={"b.txt~"}, note="review C1: the backup is the tool's, the file is still destroyed"),
             ex("install -D a.txt deep/er/a.txt", creates={"deep", "deep/er", "deep/er/a.txt"}),
         )),
    Rule(id="sed", tools=("sed",), resolver="sed",
         options=OptionSpec(
             values={"-e": "expression", "--expression": "expression", "-f": "file",
                     "--file": "file", "-l": "line_length", "--line-length": "line_length"},
             attached={"-i": "in_place"},
             flags={**_HELP, "--in-place": "in_place", "-n": "quiet", "--quiet": "quiet",
                    "--silent": "quiet", "-E": "extended", "-r": "extended",
                    "--regexp-extended": "extended", "-s": "separate", "--separate": "separate",
                    "-u": "unbuffered", "--unbuffered": "unbuffered", "-z": "null_data",
                    "--null-data": "null_data", "--posix": "posix", "--debug": "debug",
                    "--sandbox": "sandbox", "--follow-symlinks": "follow_symlinks"}),
         examples=(
             ex("sed -i s/a/b/ a.txt", destroys={"a.txt"}),
             ex("sed s/a/b/ a.txt", note="no -i: sed only prints"),
             ex("sed -i.bak s/a/b/ a.txt", destroys={"a.txt"}, creates={"a.txt.bak"},
                note="VERIFIED backup - review C1: the backup is the tool's, the file is still destroyed"),
             ex("sed -i.bak s/a/b/ x.txt", destroys={"x.txt", "x.txt.bak"}, note="review fix 1"),
             ex("sed -i -e s/a/b/ a.txt b.txt", destroys={"a.txt", "b.txt"}),
             ex("sed -i s/a/b/ missing.txt", note="absent: nothing"),
             ex("sed -ie s/a/b/ a.txt", destroys={"a.txt"}, creates={"a.txte"},
                note="GNU: -ie is -i with suffix e"),
             ex("sed --in-place=.orig s/a/b/ a.txt", destroys={"a.txt"}, creates={"a.txt.orig"}),
         )),
    Rule(id="perl", tools=("perl",), resolver="perl",
         options=OptionSpec(
             values={"-e": "code", "-E": "code", "-I": "include"},
             attached={"-i": "in_place", "-l": "line_end", "-0": "record_sep", "-F": "split",
                       "-x": "extract", "-C": "unicode", "-d": "debugger", "-D": "debug_flags",
                       "-M": "module", "-m": "module"},
             flags={"-n": "n", "-p": "p", "-a": "a", "-c": "c", "-s": "s", "-t": "t", "-T": "t",
                    "-u": "u", "-U": "u", "-v": "v", "-w": "w", "-W": "w", "-X": "x", "-S": "s",
                    "-h": "help"}),
         examples=(
             ex("perl -pi -e 's/a/b/' a.txt", destroys={"a.txt"}),
             ex("perl -pe 's/a/b/' a.txt", uncovered={"perl (code)"},
                note="without -i perl runs code: uncovered, like any interpreter"),
             ex("perl -pi.bak -e 's/a/b/' a.txt", destroys={"a.txt"}, creates={"a.txt.bak"},
                note="review C1: the backup is the tool's, the file is still destroyed"),
         )),
    Rule(id="prettier", tools=("prettier",), resolver="formatter", verified=False,
         options=OptionSpec(
             values={k: k[2:].replace("-", "_") for k in (
                 "--config", "--ignore-path", "--plugin", "--parser", "--print-width",
                 "--tab-width", "--stdin-filepath", "--log-level", "--cache-location",
                 "--cache-strategy", "--config-precedence", "--end-of-line", "--trailing-comma",
                 "--arrow-parens", "--quote-props", "--prose-wrap",
                 "--html-whitespace-sensitivity", "--embedded-language-formatting")},
             flags={"--write": "write", "-w": "write", "--check": "check", "-c": "check",
                    "--list-different": "list_different", "-l": "list_different"}),
         examples=(
             ex("prettier --write src/app.js", destroys={"src/app.js"}),
             ex("prettier src/app.js", note="no --write: prints"),
             ex("prettier --check .", note="--check writes nothing"),
             ex("prettier --write src", destroys={"src/"}, note="a directory: WITHIN"),
             ex("prettier --write 'src/**/*.js'", destroys={"src/"},
                note="a quoted glob the tool expands: WITHIN its static directory"),
         )),
    Rule(id="eslint", tools=("eslint",), resolver="formatter", verified=False,
         options=OptionSpec(
             values={"-c": "config", "--config": "config", "--ext": "ext", "--parser": "parser",
                     "--parser-options": "parser_options", "--resolve-plugins-relative-to": "rp",
                     "--rulesdir": "rulesdir", "--plugin": "plugin", "--rule": "rule",
                     "--ignore-path": "ignore_path", "--ignore-pattern": "ignore_pattern",
                     "-f": "format", "--format": "format", "-o": "output_file",
                     "--output-file": "output_file", "--max-warnings": "max_warnings",
                     "--cache-location": "cache_location", "--cache-strategy": "cache_strategy",
                     "--env": "env", "--global": "global", "--stdin-filename": "stdin_filename"},
             flags={"--fix": "fix", "--fix-dry-run": "fix_dry_run"}),
         examples=(
             ex("eslint --fix src", destroys={"src/"}),
             ex("eslint src", note="no --fix: reports only"),
             ex("eslint -o report.txt src", creates={"report.txt"}),
         )),
    Rule(id="black", tools=("black",), resolver="formatter", verified=False,
         options=OptionSpec(
             values={"-l": "line_length", "--line-length": "line_length", "-t": "target_version",
                     "--target-version": "target_version", "--config": "config",
                     "--include": "include", "--exclude": "exclude",
                     "--extend-exclude": "extend_exclude", "--force-exclude": "force_exclude",
                     "--stdin-filename": "stdin_filename", "-W": "workers", "--workers": "workers",
                     "--required-version": "required_version", "-c": "code", "--code": "code",
                     "--python-cell-magics": "cell_magics"},
             flags={"--check": "check", "--diff": "diff", "--version": "version", "-h": "help",
                    "--help": "help"}),
         examples=(
             ex("black src", destroys={"src/"}),
             ex("black --check src", note="--check writes nothing"),
             ex("black src/app.py", note="absent: nothing"),
         )),
    Rule(id="isort", tools=("isort",), resolver="formatter", verified=False,
         options=OptionSpec(
             values={"--settings-path": "settings", "--sp": "settings", "-l": "line_length",
                     "--line-length": "line_length", "--profile": "profile", "-p": "project",
                     "--project": "project", "--src": "src", "--skip": "skip",
                     "--skip-glob": "skip_glob"},
             flags={"-c": "check_only", "--check-only": "check_only", "--check": "check_only",
                    "--diff": "diff", "--show-files": "show_files", "--version": "version",
                    "--stdout": "stdout"}),
         examples=(
             ex("isort src", destroys={"src/"}),
             ex("isort --check-only src", note="checks only"),
         )),
    Rule(id="rustfmt", tools=("rustfmt",), resolver="formatter", verified=False,
         options=OptionSpec(
             values={"--edition": "edition", "--config": "config", "--config-path": "config_path",
                     "--emit": "emit", "--color": "color"},
             flags={"--check": "check", "-V": "version", "--version": "version"}),
         examples=(
             ex("rustfmt main.go", destroys={"main.go"}, note="rustfmt rewrites its operand"),
             ex("rustfmt --check main.go", note="checks only"),
             ex("rustfmt --emit stdout main.go", note="prints only"),
         )),
    Rule(id="gofmt", tools=("gofmt",), resolver="formatter",
         options=OptionSpec(values={"-r": "rule", "-cpuprofile": "cpuprofile"},
                            flags={"-w": "write", "-l": "list", "-d": "diff", "-e": "errors",
                                   "-s": "simplify"}),
         examples=(
             ex("gofmt -w main.go", destroys={"main.go"}),
             ex("gofmt -l .", note="lists only"),
             ex("gofmt main.go", note="prints only"),
         )),
    Rule(id="tee", tools=("tee",), resolver="tee",
         options=OptionSpec(values={}, flags={**_HELP, "-a": "append", "--append": "append",
                                             "-i": "ignore_int", "--ignore-interrupts": "ignore_int",
                                             "-p": "p", "--output-error": "output_error"}),
         when={"flags_none_before_operands": ("help", "version")},
         examples=(
             ex("echo x | tee a.txt", destroys={"a.txt"}),
             ex("echo x | tee -a a.txt", changes={"a.txt"}, note="VERIFIED: -a appends"),
             ex("echo x | tee new.txt", creates={"new.txt"}),
             ex("echo x | tee a.txt b.txt", destroys={"a.txt", "b.txt"}),
             ex("echo x | tee /dev/null", note="a sink"),
         )),
    Rule(id="truncate", tools=("truncate",), resolver="truncate",
         options=OptionSpec(values={"-s": "size", "--size": "size", "-r": "reference",
                                    "--reference": "reference"},
                            flags={**_HELP, "-c": "no_create", "--no-create": "no_create",
                                   "-o": "io_blocks", "--io-blocks": "io_blocks"}),
         when={"flags_none_before_operands": ("help", "version")},
         examples=(
             ex("truncate -s 0 a.txt", destroys={"a.txt"}),
             ex("truncate -s +10 a.txt", changes={"a.txt"}, note="growing loses nothing"),
             ex("truncate -s 1M a.txt", changes={"a.txt"}, note="larger than the file: it grows"),
             ex("truncate -c -s 0 new.txt", note="-c: no file is created"),
             ex("truncate -s 0 new.txt", creates={"new.txt"}),
             ex("truncate -s -1 a.txt", destroys={"a.txt"}),
         )),
    Rule(id="shred", tools=("shred",), resolver="shred",
         options=OptionSpec(values={"-n": "iterations", "--iterations": "iterations",
                                    "-s": "size", "--size": "size",
                                    "--random-source": "random_source"},
                            flags={**_HELP, "-u": "remove", "--remove": "remove", "-z": "zero",
                                   "--zero": "zero", "-x": "exact", "--exact": "exact",
                                   "-f": "force", "--force": "force", "-v": "verbose",
                                   "--verbose": "verbose"}),
         when={"flags_none_before_operands": ("help", "version")},
         examples=(
             ex("shred a.txt", destroys={"a.txt"}),
             ex("shred -u a.txt", destroys={"a.txt"}),
             ex("shred missing.txt", note="absent: nothing"),
             ex("shred dir", note="a directory: shred refuses"),
         )),
    Rule(id="touch", tools=("touch",), effects=(EffectT(CREATE),),
         options=OptionSpec(values={"-d": "date", "--date": "date", "-r": "reference",
                                    "--reference": "reference", "-t": "stamp", "--time": "time"},
                            flags={**_HELP, "-a": "a", "-c": "no_create", "--no-create": "no_create",
                                   "-h": "no_deref", "--no-dereference": "no_deref", "-m": "m"}),
         when={"flags_none": ("no_create",), "flags_none_before_operands": ("help", "version")},
         examples=(
             ex("touch new.txt", creates={"new.txt"}),
             ex("touch a.txt", note="VERIFIED: an existing file keeps its content"),
             ex("touch -c new.txt", note="-c: nothing is created"),
             ex("touch -r a.txt new.txt", creates={"new.txt"}, note="a.txt is -r's value"),
         )),
    Rule(id="mkdir", tools=("mkdir",), effects=(EffectT(MKDIR),),
         options=OptionSpec(values={"-m": "mode", "--mode": "mode"},
                            flags={**_HELP, "-p": "parents", "--parents": "parents",
                                   "-v": "verbose", "--verbose": "verbose", "-Z": "context",
                                   "--context": "context"}),
         when={"flags_none_before_operands": ("help", "version")},
         examples=(
             ex("mkdir newdir", creates={"newdir"}),
             ex("mkdir dir", note="exists: mkdir fails, nothing changes"),
             ex("mkdir -p dir", note="VERIFIED: exists, nothing happens"),
             ex("mkdir -p x/y/z", creates={"x", "x/y", "x/y/z"}),
             ex("mkdir x/y", note="no -p and no x: mkdir fails"),
             ex("mkdir n && touch n/f && rm -rf n", creates={"n", "n/f"},
                note="all of it new: nothing lost (n and n/f MAY remain, if rm fails)"),
         )),
    Rule(id="dd", tools=("dd",), resolver="dd", options=OptionSpec(),
         examples=(
             ex("dd if=a.txt of=b.txt", destroys={"b.txt"}),
             ex("dd if=a.txt of=new.bin", creates={"new.bin"}),
             ex("dd if=a.txt", note="no of=: stdout"),
             ex("dd if=a.txt of=/dev/null", note="a sink"),
             ex("dd if=/dev/zero of=/dev/sda bs=1M", remote=True, note="a disk: ESCALATE", posix_only=True),
         )),
    Rule(id="curl", tools=("curl",), resolver="curl",
         options=OptionSpec(values=_g.CURL_VALUES, flags=_g.CURL_FLAGS),
         examples=(
             ex("curl -o a.txt https://h/x", destroys={"a.txt"}),
             ex("curl -o new.txt https://h/x", creates={"new.txt"}),
             ex("curl https://h/x", note="stdout"),
             ex("curl -o - https://h/x", note="stdout"),
             ex("curl -O https://h/d/a.txt", destroys={"a.txt"}),
             ex("curl -O https://h/d/", note="no name: curl fails"),
             ex("curl -C - -o a.txt https://h/x", changes={"a.txt"}, note="resumes: appends"),
             ex("curl -OJ https://h/x", unknown=True, note="the server names the file"),
             ex("curl -c jar.txt https://h/x", creates={"jar.txt"}),
             ex("curl --output-dir sub -O https://h/a.txt", creates={"sub/a.txt"}),
         )),
    Rule(id="wget", tools=("wget",), resolver="wget",
         options=OptionSpec(values=_g.WGET_VALUES, flags=_g.WGET_FLAGS),
         examples=(
             ex("wget https://h/a.txt", creates={"a.txt.1"},
                note="VERIFIED (man): never clobbers, saves a.txt.1"),
             ex("wget https://h/new.txt", creates={"new.txt"}),
             ex("wget -O a.txt https://h/x", destroys={"a.txt"}),
             ex("wget -N https://h/a.txt", destroys={"a.txt"}),
             ex("wget -nc https://h/a.txt", note="-nc: nothing"),
             ex("wget -r https://h/", unknown=True),
             ex("wget -O - https://h/x", note="stdout"),
         )),
    Rule(id="rsync", tools=("rsync",), resolver="rsync", partial=None,
         options=OptionSpec(
             values={k: k.lstrip("-").replace("-", "_") for k in (
                 "-e", "--rsh", "--rsync-path", "--exclude", "--include", "-f", "--filter",
                 "--exclude-from", "--include-from", "--files-from", "-T", "--temp-dir",
                 "--partial-dir", "--backup-dir", "--suffix", "--chmod", "--chown", "--usermap",
                 "--groupmap", "--timeout", "--contimeout", "--bwlimit", "--max-size",
                 "--min-size", "--max-delete", "--compare-dest", "--copy-dest", "--link-dest",
                 "-B", "--block-size", "--out-format", "--log-file", "--log-file-format",
                 "--password-file", "--port", "--sockopts", "--info", "--debug", "--write-batch",
                 "--only-write-batch", "--read-batch", "--protocol", "--iconv",
                 "--checksum-choice", "--compress-choice", "--compress-level", "--skip-compress",
                 "-M", "--remote-option", "--modify-window", "--outbuf", "--address",
                 "--stop-after", "--stop-at")},
             flags={"-n": "dry_run", "--dry-run": "dry_run", "-b": "backup", "--backup": "backup",
                    "--remove-source-files": "remove_source_files",
                    "--ignore-existing": "ignore_existing", "--list-only": "list_only",
                    # M2.2f: the whole --del* family (rsync(1), rsync 3.5.0)
                    **{d: "delete" for d in (
                        "--del", "--delete", "--delete-before", "--delete-during",
                        "--delete-delay", "--delete-after", "--delete-excluded",
                        "--delete-missing-args")}}),
         examples=(
             ex("rsync -a sub/ dir/", destroys={"dir/"}, note="into an existing dir: WITHIN"),
             ex("rsync -an sub/ dir/", note="--dry-run"),
             ex("rsync -a sub/ newdir/", creates={"newdir"}),
             ex("rsync a.txt b.txt", destroys={"b.txt"}),
             ex("rsync -b a.txt b.txt", destroys={"b.txt"}, creates={"b.txt~"},
                note="review C1: --backup keeps the tool's copy; b.txt is still destroyed"),
             ex("rsync -b a.txt x.txt", destroys={"x.txt", "x.txt~"}, note="review fix 1"),
             ex("rsync --ignore-existing a.txt b.txt", note="an existing file is kept"),
             ex("rsync -b --backup-dir=old a.txt b.txt", destroys={"b.txt"}, unknown=True,
                note="where --backup-dir puts the backup is not modelled"),
             ex("rsync -a sub/ host:/x", reaches={"host:host": OVERWRITE},
                note="M2.2f, ruling R8: a push changes the host"),
             ex("rsync -a --delete sub/ deploy@web1:/srv/", reaches={"host:web1": DELETE}),
             ex("rsync -a --del sub/ rsync://web1/mod/", reaches={"host:web1": DELETE}),
             ex("rsync -an --delete sub/ web1:/srv/", note="--dry-run: nothing changes"),
             ex("rsync -a web1:/srv/ dir/", destroys={"dir/"}, note="a pull: a local write, captured"),
         )),
    Rule(id="tar", tools=("tar",), resolver="tar", options=TAR_OPTIONS,
         examples=(
             ex("tar -xf a.tar", unknown=True, note="the archive names the files"),
             ex("tar -xkf a.tar", note="VERIFIED: -k keeps existing files: only creations"),
             ex("tar xf a.tar", unknown=True, note="old-style bundled options"),
             ex("tar -czf out.tgz dir", creates={"out.tgz"}),
             ex("tar -czf a.txt dir", destroys={"a.txt"}),
             ex("tar -czf x.tgz dir --remove-files", destroys={"dir/"}, creates={"x.tgz"}),
             ex("tar -tf a.tar", note="lists only"),
             ex("tar -xf a.tar -O", note="to stdout"),
             ex("tar -xf a.tar a.txt", destroys={"a.txt"}, note="a named member"),
             ex("tar -xf a.tar --after-date a.txt", unknown=True,
                note="an alias taking a value: a.txt is its DATE-OR-FILE, not a member"),
             ex("tar --get -f a.tar", unknown=True, note="--get is --extract"),
         )),
    Rule(id="unzip", tools=("unzip",), resolver="unzip", options=OptionSpec(),
         examples=(
             ex("unzip m.zip", creates={"new.txt"},
                note="VERIFIED: no terminal, the prompt reads EOF: nothing overwritten"),
             ex("unzip -o m.zip", destroys={"a.txt"}, creates={"new.txt"}),
             ex("unzip -o -Psecret m.zip", destroys={"a.txt"}, creates={"new.txt"},
                note="I1c: P takes the rest of the word, here a password"),
             ex("unzip -oPsecret m.zip", destroys={"a.txt"}, creates={"new.txt"},
                note="I1c: -o, then the password secret"),
             ex("unzip -Pxo m.zip", creates={"new.txt"},
                note="I1c: xo is the password, not -x -o: nothing is overwritten"),
             ex("unzip -n m.zip", creates={"new.txt"}),
             ex("unzip -o m.zip -d sub", creates={"sub/a.txt", "sub/new.txt"}),
             ex("unzip -l m.zip", note="lists only"),
             ex("unzip zs.zip", destroys={"../evil.txt"}, note="zip-slip: outside, ESCALATE"),
             ex("unzip sl.zip", unknown=True, note="a symlink member"),
             ex("unzip missing.zip", note="no archive: unzip fails"),
         )),
    Rule(id="find", tools=("find",), resolver="find", options=OptionSpec(),
         examples=(
             ex("find dir -name '*.txt' -delete", destroys={"dir/"}),
             ex("find dir -name x", note="no action: prints"),
             ex("find dir -exec rm {} \\;", destroys={"dir/"}),
             ex("find dir -exec cat {} \\;", note="reads only"),
             ex("find dir -exec sh -c 'rm \"$1\"' _ {} \\;", unknown=True),
             ex("find dir -fprint out.txt", creates={"out.txt"}),
             ex("find missing -delete", note="nothing there"),
         )),
)
RULES = RULES + C1_RULES



# ==========================================================================
# Families loaded only when one of their tools is met (C2a on). A hook call
# that meets none of them pays nothing for their grammars and examples.
# ==========================================================================
LAZY_FAMILIES: Dict[str, str] = {
    "sqlite3": "rules_sql", "psql": "rules_sql", "mysql": "rules_sql", "mariadb": "rules_sql",
    "git": "rules_git",
    "terraform": "rules_infra", "tofu": "rules_infra", "kubectl": "rules_infra",
    "helm": "rules_infra", "pulumi": "rules_infra", "cdk": "rules_infra",
    "aws": "rules_cloud", "s3cmd": "rules_cloud", "rclone": "rules_cloud", "mc": "rules_cloud",
    "gcloud": "rules_cloud2", "gsutil": "rules_cloud2", "az": "rules_cloud2",
    "azcopy": "rules_cloud2", "railway": "rules_cloud2",
    "docker": "rules_container", "podman": "rules_container", "docker-compose": "rules_container",
    "redis-cli": "rules_datastore", "mongosh": "rules_datastore", "mongo": "rules_datastore",
    "dropdb": "rules_datastore", "pg_restore": "rules_datastore", "pg_dump": "rules_datastore",
    "mysqladmin": "rules_datastore", "sqlcmd": "rules_datastore",
    # M2.2b4b2: stores, CMS, payments, migrations
    "shopify": "rules_saas", "wp": "rules_saas", "stripe": "rules_saas", "rails": "rules_saas", "rake": "rules_saas", "manage.py": "rules_saas", "django-admin": "rules_saas", "alembic": "rules_saas", "prisma": "rules_saas", "knex": "rules_saas", "flyway": "rules_saas", "liquibase": "rules_saas",
    # M2.2b4b1: PaaS CLIs
    "heroku": "rules_paas", "fly": "rules_paas", "flyctl": "rules_paas", "vercel": "rules_paas", "vc": "rules_paas", "netlify": "rules_paas", "wrangler": "rules_paas", "firebase": "rules_paas",
    # M2.2b4a: what leaves the machine
    "http": "rules_send", "https": "rules_send", "xh": "rules_send", "xhs": "rules_send", "gh": "rules_send", "mail": "rules_send",
    "mailx": "rules_send", "sendmail": "rules_send", "swaks": "rules_send", "ssh": "rules_send", "scp": "rules_send", "sftp": "rules_send",
    "npm": "rules_send", "pnpm": "rules_send", "yarn": "rules_send", "cargo": "rules_send", "twine": "rules_send", "gem": "rules_send",
    "poetry": "rules_send",
    # M2.2f: vault; the Django runner in front of manage.py
    "vault": "rules_vault", "python": "rules_saas", "python3": "rules_saas", "py": "rules_saas",
    # M2.2d: schedulers - code that runs later
    "crontab": "rules_system", "at": "rules_system", "batch": "rules_system", "atq": "rules_system",
    "atrm": "rules_system", "schtasks": "rules_system", "systemd-run": "rules_system",
    # M2.2c: services, power, processes, accounts, disks, recovery data,
    # network and firewall, modes and owners, the Windows registry
    "addgroup": "rules_system", "adduser": "rules_system", "bcdedit": "rules_system",
    "blkdiscard": "rules_system", "chage": "rules_system", "chfn": "rules_system",
    "chgpasswd": "rules_system", "chgrp": "rules_system", "chmod": "rules_system",
    "chown": "rules_system", "chpasswd": "rules_system", "chsh": "rules_system",
    "cipher": "rules_system", "delgroup": "rules_system", "deluser": "rules_system",
    "diskpart": "rules_system", "fdisk": "rules_system", "format": "rules_system",
    "format.com": "rules_system", "gpasswd": "rules_system", "groupadd": "rules_system",
    "groupdel": "rules_system", "groupmod": "rules_system", "halt": "rules_system",
    "icacls": "rules_system", "ifconfig": "rules_system", "ip": "rules_system",
    "ip6tables": "rules_system", "ip6tables-legacy": "rules_system",
    "ip6tables-nft": "rules_system", "ip6tables-restore": "rules_system",
    "ip6tables-save": "rules_system", "iptables": "rules_system",
    "iptables-legacy": "rules_system", "iptables-nft": "rules_system",
    "iptables-restore": "rules_system", "iptables-save": "rules_system", "kill": "rules_system",
    "killall": "rules_system", "killall5": "rules_system", "launchctl": "rules_system",
    "mkdosfs": "rules_system", "mke2fs": "rules_system", "mkfs": "rules_system",
    "mkfs.btrfs": "rules_system", "mkfs.exfat": "rules_system", "mkfs.ext2": "rules_system",
    "mkfs.ext3": "rules_system", "mkfs.ext4": "rules_system", "mkfs.f2fs": "rules_system",
    "mkfs.fat": "rules_system", "mkfs.msdos": "rules_system", "mkfs.ntfs": "rules_system",
    "mkfs.vfat": "rules_system", "mkfs.xfs": "rules_system", "mkntfs": "rules_system",
    "mkswap": "rules_system", "net": "rules_system", "net1": "rules_system",
    "netsh": "rules_system", "newusers": "rules_system", "nft": "rules_system",
    "nmcli": "rules_system", "parted": "rules_system", "passwd": "rules_system",
    "pkill": "rules_system", "poweroff": "rules_system", "reboot": "rules_system",
    "reg": "rules_system", "sc": "rules_system", "service": "rules_system",
    "sfdisk": "rules_system", "shutdown": "rules_system", "systemctl": "rules_system",
    "takeown": "rules_system", "taskkill": "rules_system", "ufw": "rules_system",
    "useradd": "rules_system", "userdel": "rules_system", "usermod": "rules_system",
    "vssadmin": "rules_system", "wbadmin": "rules_system", "wevtutil": "rules_system",
    "wipefs": "rules_system", "wmic": "rules_system",
}
_FAMILY_RULES: Dict[str, Tuple[Rule, ...]] = {}


def family_rules(module: str) -> Tuple[Rule, ...]:
    rules = _FAMILY_RULES.get(module)
    if rules is None:
        import importlib
        rules = importlib.import_module(f"{__package__}.{module}").FAMILY_RULES
        _FAMILY_RULES[module] = rules
    return rules


def all_rules() -> Tuple[Rule, ...]:
    """Every rule, lazy families included (tests and tooling)."""
    out = RULES
    for module in dict.fromkeys(LAZY_FAMILIES.values()):
        out = out + family_rules(module)
    return out

# Kept for the Part B semantics tests, which used to add touch and mv here.
TEST_ONLY_RULES: Tuple[Rule, ...] = RULES


def shell_prefilter_words() -> Tuple[str, ...]:
    """The command words the shell guard's prefilter sends to guard-shell
    (M2.2e): every tool a rule covers, lazy families included, and the
    wrappers that can put one behind them (sudo, env, timeout ...) - minus
    the reads and the shells, which have no effect of their own, and git,
    whose prefilter is generated from classify.py's git rules so a read like
    `git status` costs nothing. Generated from the tables, never typed: a
    family added later reaches the shell door by being added here."""
    from ..classify import _WRAPPERS
    words = set(LAZY_FAMILIES) | {t for r in RULES for t in r.tools} | set(_WRAPPERS)
    return tuple(sorted(words - READ_ONLY - SHELLS - {"git"} - _RUNNERS))


# Interpreters: a rule claims only a narrow use of them (M2.2f: python
# manage.py), and sending every `python x.py` typed in a shell to guard-shell
# (~0.4 s each) is M2.3's decision, made with real numbers.
_RUNNERS = frozenset({"python", "python3", "py"})
