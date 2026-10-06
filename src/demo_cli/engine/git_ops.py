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
command the old rules catch into a silent ALLOW. `git config` is left
uncovered ON PURPOSE: it can plant code that runs later (hooksPath, an
alias starting with `!`), which is M2.2d's effect kind, and claiming to
understand it here would lose what the old path catches today.

HISTORY INSIDE .git (ruling (c), 2026-10-06). .git is in IGNORED_DIRS, so a
recovery point cannot hold it, and demo_cli never claims a recovery it does
not have. So a rewrite the reflog brings back is recorded as a REF reach,
which policy allows and the receipt lists; a command that destroys the
reflog ITSELF - the thing that makes the others recoverable - is a surface
no local copy restores, and escalates.
"""
from __future__ import annotations

import os
from typing import List, Optional, Tuple

from ..model import Word
from .effects import CREATE, DELETE, OVERWRITE, REF
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
        if name in _GLOBAL_VALUE:
            value = glued if eq else (args[i + 1].value if i + 1 < len(args) else "")
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


def git(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    idx, cwd = _globals(w, inv, args, state)
    if idx is None:
        return
    sub = args[idx].value
    rest = args[idx + 1:]
    if any(a.expands for a in rest):
        w.impact.not_understood(inv.text, f"a git {sub} argument named by an expansion")
        return
    # The subcommand runs where `-C` left us, not where the hook stands.
    if cwd != state.cwd:
        state = state.copy()
        state.cwd = cwd
    root = _repo_root(w, state, cwd)

    if sub in _READ_ONLY:
        return
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
