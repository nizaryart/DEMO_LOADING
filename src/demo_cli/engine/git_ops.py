"""What a git subcommand does, in the engine's own effect language (M2.2a).

git is one command word with three different blast radii - the working tree,
the refs inside .git, and a remote - and its own options come BEFORE the
subcommand, so `git -C dir push --force` is a force push and a text rule
anchored on `git push` never sees it. A rule template cannot express that;
this module is the `git` resolver's implementation.

WHAT IT CLAIMS, AND WHAT IT DOES NOT. A subcommand this module does not
list is reported as `uncovered`, exactly as an unknown tool is, so
Guard._engine_applies is False and today's text path decides that line
unchanged. The table can only ever ADD understanding; it cannot turn a
command the old rules catch into a silent ALLOW.

`git config` (M2.2d, rulings D1-D2): a key whose value git RUNS - hooksPath,
an alias, a pager or editor, a filter, a credential helper, an include - is
code that runs later, unnamed: LATER on `later:git-config@<scope>`
(deferred_execution, ask). Any other key changes nothing a person would undo
(the old path allowed every `git config` too); reads read. The same keys
given for ONE command (`git -c core.pager=... log`, `--config-env`) run now,
unread: not understood, and today's path decides. VERIFIED against
git-config(1) and gitattributes(5) of git 2.51: the subcommand form (list /
get / set / unset / rename-section / remove-section / edit), the option form,
the file options, and every key below is documented there as a command,
program, helper, hook path or include.

HISTORY INSIDE .git (ruling (c), 2026-10-06). .git is in IGNORED_DIRS, so a
recovery point cannot hold it, and demo_cli never claims a recovery it does
not have. So a rewrite the reflog brings back is recorded as a REF reach,
which policy allows and the receipt lists; a command that destroys the
reflog ITSELF - the thing that makes the others recoverable - is a surface
no local copy restores, and escalates.
"""
from __future__ import annotations

import os
import re
from typing import List, Optional, Tuple

from ..model import Word
from .effects import CREATE, DELETE, LATER, OVERWRITE, REF
from .simulate import _host_path

# git's own options, which sit between `git` and the subcommand.
_GLOBAL_VALUE = frozenset({
    "-C", "-c", "--git-dir", "--work-tree", "--exec-path", "--namespace",
    "--super-prefix", "--config-env", "--attr-source",
})
_GLOBAL_FLAG = frozenset({
    "-p", "-P", "--paginate", "--no-pager", "--bare", "--no-replace-objects",
    "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs",
    "--icase-pathspecs", "--no-optional-locks", "--no-lazy-fetch",
    "--no-advice", "--html-path", "--man-path", "--info-path", "--version",
    "--help", "-h",
})

# Subcommands that read and change nothing. Everything else must be listed in
# the dispatch table below or it is reported as uncovered.
_READ_ONLY = frozenset({
    "status", "log", "show", "diff", "shortlog", "describe", "blame",
    "rev-parse", "rev-list", "ls-files", "ls-tree", "ls-remote", "cat-file",
    "for-each-ref", "symbolic-ref", "name-rev", "whatchanged", "grep",
    "bisect", "help", "version", "var", "check-ignore", "check-attr",
    "verify-commit", "verify-tag", "count-objects", "fsck", "annotate",
    "cherry", "difftool", "instaweb", "request-pull", "range-diff",
})

# A reflog entry brings these back (ruling (c)): the receipt lists them.
_REFLOG_RECOVERABLE = frozenset({
    "commit", "merge", "pull", "rebase", "cherry-pick", "revert", "am",
    "fetch", "remote", "submodule", "notes", "replace", "fast-import",
    "repack", "prune-packed", "pack-refs", "symbolic-ref",
})

_FORCE = frozenset({"-f", "--force"})


def _dir_value(w, state, raw: str) -> Optional[str]:
    """A directory operand as an absolute path, or None when it cannot be
    pinned down (a Git Bash path with no Windows mapping, or no cwd)."""
    p = _host_path(raw)
    if p is None:
        return None
    if os.path.isabs(p):
        return os.path.normpath(p)
    if state.cwd is None:
        return None
    return os.path.normpath(os.path.join(state.cwd, p))


def _repo_root(w, state, cwd: Optional[str]) -> Optional[str]:
    """The directory holding .git at or above `cwd`, read from the filesystem
    the way context.py does - the engine never spawns git. None when there is
    no repository above cwd: then nothing here applies."""
    if cwd is None:
        return None
    cur = cwd
    for _ in range(64):
        if w.node(state, os.path.join(cur, ".git")).exists:
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent
    return None


def _globals(w, inv, args: List[Word], state) -> Tuple[Optional[int], Optional[str]]:
    """(index of the subcommand, cwd it runs in), or (None, _) when a global
    option cannot be read. `-C` is applied in order, as git does: two of them
    are relative to each other."""
    cwd = state.cwd
    i = 0
    while i < len(args):
        word = args[i]
        v = word.value
        if word.expands:
            w.impact.not_understood(inv.text, "a git option named by an expansion")
            return None, cwd
        if not v.startswith("-"):
            return i, cwd
        name, eq, glued = v.partition("=")
        if name == "--exec-path" and eq:
            w.impact.not_understood(inv.text, "git --exec-path runs the programs it finds there")
            return None, cwd
        if name in _GLOBAL_VALUE:
            value = glued if eq else (args[i + 1].value if i + 1 < len(args) else "")
            if name in ("-c", "--config-env") and runs_code(value.split("=", 1)[0]):
                w.impact.not_understood(inv.text, f"git {name} sets a command that runs now, unread")
                return None, cwd
            if name == "-C":
                if not value:
                    w.impact.not_understood(inv.text, "git -C without a directory")
                    return None, cwd
                nxt = _dir_value(w, state, value) if cwd is not None else None
                if nxt is None:
                    w.impact.not_understood(inv.text, "git -C into a directory this engine cannot resolve")
                    return None, cwd
                cwd = nxt
            elif name in ("--git-dir", "--work-tree"):
                # They move the repository or the tree somewhere this module
                # does not follow: refuse rather than answer for the wrong tree.
                w.impact.not_understood(inv.text, f"git {name} points at another tree")
                return None, cwd
            i += 1 if eq else 2
            continue
        if name in _GLOBAL_FLAG:
            i += 1
            continue
        w.impact.not_covered("git (option)")
        return None, cwd
    w.impact.not_covered("git")                   # `git` with no subcommand
    return None, cwd


# git-config(1) / gitattributes(5): keys whose value is a command, a program,
# a helper, a hook path, a template directory or an included config file.
# (section, subsection or None for "none", variable); "*" matches anything;
# compared lower-case (sections and variables are case-insensitive).
_CODE_KEYS = (
    ("alias", "*", "*"), ("alias", None, "*"),
    ("core", None, "hookspath"), ("core", None, "editor"), ("core", None, "pager"),
    ("core", None, "sshcommand"), ("core", None, "fsmonitor"), ("core", None, "askpass"),
    ("core", None, "gitproxy"), ("sequence", None, "editor"), ("diff", None, "external"),
    ("diff", "*", "command"), ("diff", "*", "textconv"), ("merge", "*", "driver"),
    ("filter", "*", "clean"), ("filter", "*", "smudge"), ("filter", "*", "process"),
    ("credential", None, "helper"), ("credential", "*", "helper"),
    ("pager", None, "*"), ("gpg", None, "program"), ("gpg", "*", "program"),
    ("gpg", "ssh", "defaultkeycommand"), ("browser", "*", "cmd"), ("difftool", "*", "cmd"),
    ("mergetool", "*", "cmd"), ("man", "*", "cmd"), ("guitool", "*", "cmd"),
    ("trailer", "*", "cmd"), ("trailer", "*", "command"),
    ("uploadpack", None, "packobjectshook"), ("interactive", None, "difffilter"),
    ("init", None, "templatedir"), ("include", None, "path"), ("includeif", "*", "path"),
    ("remote", "*", "receivepack"), ("remote", "*", "uploadpack"), ("remote", "*", "vcs"),
    ("web", None, "browser"), ("submodule", "*", "update"),
)
_CODE_SECTIONS = frozenset(k[0] for k in _CODE_KEYS)


def runs_code(key: str) -> bool:
    """Does git run the value of `key` as a program (or read it as one)?"""
    parts = key.split(".")
    if len(parts) < 2:
        return False
    section, var = parts[0].lower(), parts[-1].lower()
    sub = ".".join(parts[1:-1]) or None
    for s_, sub_, v_ in _CODE_KEYS:
        if s_ != section:
            continue
        if sub_ is None and sub is not None:
            continue
        if sub_ == "*" and sub is None:
            continue
        if sub_ not in (None, "*") and (sub or "").lower() != sub_:
            continue
        if v_ in ("*", var):
            return True
    return False


_CONFIG_SUBCOMMANDS = frozenset({"list", "get", "set", "unset", "rename-section",
                                 "remove-section", "edit"})
_CONFIG_VALUES = ("--file", "--blob", "--type", "--comment", "--value", "--default", "--url")
_CONFIG_FLAGS = ("--global", "--system", "--local", "--worktree", "--all", "--regexp",
                 "--fixed-value", "--no-value", "--null", "--name-only", "--show-origin",
                 "--show-scope", "--includes", "--no-includes", "--no-type", "--bool",
                 "--int", "--bool-or-int", "--path", "--expiry-date", "--append",
                 "--replace-all", "--add", "--unset", "--unset-all", "--get", "--get-all",
                 "--get-regexp", "--get-urlmatch", "--get-color", "--get-colorbool", "--list",
                 "--rename-section", "--remove-section", "--edit", "--help")
_CONFIG_READ_MODES = frozenset({"--get", "--get-all", "--get-regexp", "--get-urlmatch",
                                "--get-color", "--get-colorbool", "--list", "--help"})


def _config(w, inv, args: List[Word]) -> None:
    """`git config`: what it plants. parse-options: a unique prefix of a long
    option is that option."""
    longs = _CONFIG_VALUES + _CONFIG_FLAGS
    sub = None
    if args and args[0].value in _CONFIG_SUBCOMMANDS:
        sub, args = args[0].value, args[1:]
    scope, modes, operands = "local", set(), []
    i = 0
    while i < len(args):
        v = args[i].value
        if v == "--":
            operands.extend(a.value for a in args[i + 1:])
            break
        if v.startswith("--"):
            name = v.split("=", 1)[0]
            hits = [o for o in longs if o == name] or [o for o in longs if o.startswith(name)]
            if len(hits) != 1:
                w.impact.not_covered("git config " + name)
                return
            name = hits[0]
            if name in ("--global", "--system", "--worktree", "--local"):
                scope = name[2:]
            if name in _CONFIG_VALUES:
                if name == "--file":
                    scope = "file"
                if name == "--blob":
                    modes.add("--blob")
                i += 1 if "=" in v else 2
                continue
            modes.add(name)
            i += 1
            continue
        if v.startswith("-") and len(v) > 1:
            for ch in v[1:]:
                if ch == "f":
                    scope = "file"
                    i += 1                                # its value is the next word
                    break
                if ch == "l":
                    modes.add("--list")
                elif ch == "e":
                    modes.add("--edit")
                elif ch in "zh":
                    pass
                else:
                    w.impact.not_covered("git config -" + ch)
                    return
            i += 1
            continue
        operands.append(v)
        i += 1
    label = f"later:git-config@{scope}"
    if sub in ("list", "get") or modes & _CONFIG_READ_MODES or "--blob" in modes:
        return
    if sub == "edit" or "--edit" in modes:
        return w.impact.reach(label, LATER)               # an editor: anything can be set
    if sub in ("unset", "remove-section") or modes & {"--unset", "--unset-all",
                                                       "--remove-section"}:
        return                                            # takes a setting away
    if sub == "rename-section" or "--rename-section" in modes:
        new = operands[1] if len(operands) > 1 else ""
        if new.split(".", 1)[0].lower() in _CODE_SECTIONS:
            w.impact.reach(label, LATER)
        return
    # set / --add / --replace-all / `git config NAME VALUE`; `git config NAME` reads
    if sub is None and not modes & {"--add", "--replace-all", "--append"} and len(operands) < 2:
        return
    if operands and runs_code(operands[0]):
        w.impact.reach(label, LATER)


def _operands(args: List[Word]) -> List[Word]:
    """The non-option words after the subcommand; everything after `--` is one."""
    out, done = [], False
    for word in args:
        if not done and word.value == "--" and not word.expands:
            done = True
            continue
        if done or not word.value.startswith("-") or word.value == "-":
            out.append(word)
    return out


def _has(args: List[Word], *names: str) -> bool:
    return any(a.value in names and not a.expands for a in args)


def _lose_tree(w, state, root: Optional[str], inv) -> None:
    """The whole working tree may lose its uncommitted content. Captured as
    the repository root: when that root IS the project root, nothing can
    capture it and the verdict escalates - which is the honest answer."""
    if root is None:
        w.impact.not_understood(inv.text, "the repository this runs in is unknown")
        return
    w.within(state, root, OVERWRITE)


def _lose_paths(w, inv, parsed, state, args: List[Word], root) -> None:
    """Named pathspecs lose their uncommitted content. A pathspec is not a
    path (it can be a glob git expands itself, `:/`, `:!x`), so anything that
    is not a plain relative path falls back to the whole tree."""
    ops = _operands(args)
    if not ops:
        return _lose_tree(w, state, root, inv)
    for word in ops:
        if word.expands or any(c in word.value for c in "*?[:"):
            return _lose_tree(w, state, root, inv)
    for p in w.paths(ops, state, inv):
        node = w.node(state, p)
        if not node.exists:
            continue
        if node.is_dir:
            w.within(state, p, OVERWRITE)
        else:
            w.replace(state, p, OVERWRITE)


def _push(w, inv, args: List[Word], state) -> None:
    """A push that only ADDS commits is allowed and listed. A push that can
    replace or delete a ref on the server is a surface no local copy restores:
    --force / -f / --force-with-lease / --mirror, a `+refspec`, or a refspec
    whose source side is empty (`:branch` deletes it), and --delete."""
    label = "vcs-remote:" + (next((a.value for a in _operands(args)), None) or "origin")
    if _has(args, "--mirror"):
        w.impact.reach(label, OVERWRITE)
        return
    if _has(args, "--delete", "-d"):
        w.impact.reach(label, DELETE)
        return
    forced = any(
        (a.value in ("-f", "--force") or a.value.startswith("--force-with-lease")
         or a.value.startswith("--force-if-includes")) and not a.expands
        for a in args)
    deletes = False
    for word in _operands(args)[1:]:              # the first operand is the remote
        if word.expands:
            w.impact.not_understood(inv.text, "a git refspec named by an expansion")
            return
        spec = word.value
        if spec.startswith("+"):
            forced = True
        if spec.startswith(":") or (":" in spec and not spec.split(":", 1)[0]):
            deletes = True
    if deletes:
        w.impact.reach(label, DELETE)
    elif forced:
        w.impact.reach(label, OVERWRITE)
    else:
        w.impact.reach(label, CREATE)


# A message is text git stores, not a name it acts on: what it expands to
# changes no effect (M2.3b). Its $( ) still runs, and the simulation reads it.
_MESSAGE_SUBS = frozenset({"commit", "tag", "stash", "merge", "notes"})


def _not_messages(sub: str, rest):
    """`rest` without the values of -m / --message (git commit / tag / stash
    push / merge / notes)."""
    if sub not in _MESSAGE_SUBS:
        return rest
    out, skip = [], False
    for a in rest:
        if skip:
            skip = False
            continue
        r = a.raw
        if r in ("-m", "--message") or re.fullmatch(r"-[A-Za-z]*m", r):
            skip = True                         # -m MSG, --message MSG, -am MSG
            continue
        if r.startswith("--message=") or re.match(r"-[A-Za-z]*m.", r) and not r.startswith("--"):
            continue                            # --message=MSG, -mMSG, -amMSG
        out.append(a)
    return out


def git(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    idx, cwd = _globals(w, inv, args, state)
    if idx is None:
        return
    sub = args[idx].value
    rest = args[idx + 1:]
    if any(a.expands for a in _not_messages(sub, rest)):
        w.impact.not_understood(inv.text, f"a git {sub} argument named by an expansion")
        return
    # The subcommand runs where `-C` left us, not where the hook stands.
    if cwd != state.cwd:
        state = state.copy()
        state.cwd = cwd
    root = _repo_root(w, state, cwd)

    if sub in _READ_ONLY:
        return
    if sub == "config":
        return _config(w, inv, rest)
    if sub == "push":
        return _push(w, inv, rest, state)
    if sub == "reset":
        # Only --hard discards the working tree; --soft/--mixed/--merge/--keep
        # keep it (--keep and --merge refuse when changes would be lost).
        if _has(rest, "--hard"):
            _lose_tree(w, state, root, inv)
        w.impact.reach("vcs-local:reset", REF)
        return
    if sub in ("checkout", "switch"):
        # A branch switch loses nothing: git refuses it when local changes
        # would be lost. Discarding is explicit: -f / --force /
        # --discard-changes, or a pathspec (`-- .`, `git checkout .`).
        if _has(rest, "--discard-changes") or _has(rest, *_FORCE):
            _lose_tree(w, state, root, inv)
            return
        if sub == "checkout" and ("--" in [a.value for a in rest] or _operands(rest)):
            ops = _operands(rest)
            # `git checkout <branch>` is a switch, not a discard: only a
            # pathspec after `--`, or an operand that names a real path, is.
            if "--" in [a.value for a in rest] or any(
                    w.node(state, p).exists for p in w.paths(ops, state, inv)):
                _lose_paths(w, inv, parsed, state, rest, root)
        return
    if sub == "restore":
        # Default is the working tree. --staged alone touches only the index.
        if _has(rest, "--staged", "-S") and not _has(rest, "--worktree", "-W"):
            return
        _lose_paths(w, inv, parsed, state, rest, root)
        return
    if sub == "clean":
        # Untracked files are removed. Which ones is in git's index, not on
        # the line, so the starting points are captured whole. Without -f (and
        # no clean.requireForce=false) git refuses; -n/--dry-run prints.
        if _has(rest, "-n", "--dry-run") or not any(
                a.value.startswith("-") and not a.value.startswith("--")
                and "f" in a.value[1:] or a.value == "--force" for a in rest):
            return
        ops = _operands(rest)
        if ops:
            for p in w.paths(ops, state, inv):
                if w.node(state, p).exists:
                    w.within(state, p, DELETE)
        else:
            _lose_tree(w, state, root, inv)
        return
    if sub == "stash":
        action = next((a.value for a in _operands(rest)), "push")
        if action in ("drop", "clear"):
            # The stash ref is gone; only a dangling object remains, which no
            # reflog lists. A surface, not a recovery.
            w.impact.reach("vcs-local:stash", DELETE)
            return
        if action in ("pop", "apply"):
            _lose_tree(w, state, root, inv)       # it writes over the working tree
            w.impact.reach("vcs-local:stash", REF)
            return
        if action in ("push", "save", "create", "store", "list", "show", "branch"):
            if action in ("push", "save"):
                _lose_tree(w, state, root, inv)   # changes move into the stash
                w.impact.reach("vcs-local:stash", REF)
            return
        w.impact.not_covered(f"git stash {action}")
        return
    if sub == "branch":
        if _has(rest, "-D") or (_has(rest, "-d", "--delete") and _has(rest, *_FORCE)):
            w.impact.reach("vcs-local:branch", REF)
        elif _has(rest, "-d", "--delete", "-m", "--move", "-M", "-c", "--copy", "-C"):
            w.impact.reach("vcs-local:branch", REF)
        return
    if sub == "tag":
        if _has(rest, "-d", "--delete"):
            w.impact.reach("vcs-local:tag", REF)
        return
    if sub == "update-ref":
        if _has(rest, "-d", "--delete"):
            w.impact.reach("vcs-local:ref", REF)
        else:
            w.impact.reach("vcs-local:ref", REF)
        return
    if sub == "reflog":
        action = next((a.value for a in _operands(rest)), "show")
        if action in ("expire", "delete"):
            # This destroys what makes every other rewrite recoverable.
            w.impact.reach("vcs-local:reflog", DELETE)
        return
    if sub == "gc":
        # Pruning with an explicit horizon drops unreachable objects now; a
        # plain `git gc` is routine maintenance and keeps the default grace.
        if any(a.value.startswith("--prune=") and a.value != "--prune=never" for a in rest):
            w.impact.reach("vcs-local:objects", DELETE)
        return
    if sub in ("filter-branch", "filter-repo"):
        w.impact.reach("vcs-local:history", OVERWRITE)
        return
    if sub == "prune":
        w.impact.reach("vcs-local:objects", DELETE)
        return
    if sub == "worktree":
        action = next((a.value for a in _operands(rest)), "list")
        if action == "remove":
            ops = _operands(rest)[1:]
            for p in w.paths(ops, state, inv):
                if w.node(state, p).exists:
                    w.within(state, p, DELETE)
            return
        if action in ("list", "lock", "unlock", "repair", "add"):
            return
        if action == "prune":
            w.impact.reach("vcs-local:objects", DELETE)
            return
        w.impact.not_covered(f"git worktree {action}")
        return
    if sub == "rm":
        # The files leave the working tree. Tracked, unmodified content comes
        # back from HEAD, but the local file is gone either way, so it is
        # recorded and captured - today this was ALLOW with nothing captured.
        ops = _operands(rest)
        if _has(rest, "--cached"):
            return                                # index only: the file stays
        for word in ops:
            if any(c in word.value for c in "*?["):
                return _lose_tree(w, state, root, inv)
        for p in w.paths(ops, state, inv):
            node = w.node(state, p)
            if not node.exists:
                continue
            if node.is_dir:
                w.within(state, p, DELETE)
            else:
                w.remove(state, p)
        return
    if sub == "mv":
        paths = w.paths(_operands(rest), state, inv)
        if len(paths) < 2:
            return
        pairs = w.dest_pairs(state, paths, parsed, inv)
        if not _has(rest, *_FORCE):
            # VERIFIED: without -f, git mv refuses a destination that exists
            # ("destination exists"), so nothing there is lost.
            pairs = [(s, d) for s, d in pairs if not w.node(state, d).exists]
        w.move(state, pairs, parsed)
        return
    if sub == "apply":
        # The patch names the files; its content is not on the line.
        if _has(rest, "--check", "--stat", "--summary", "--numstat"):
            return
        w.impact.not_understood(inv.text, "the patch names the files git apply writes")
        return
    if sub in _REFLOG_RECOVERABLE:
        w.impact.reach(f"vcs-local:{sub}", REF)
        return
    w.impact.not_covered(f"git {sub}")
