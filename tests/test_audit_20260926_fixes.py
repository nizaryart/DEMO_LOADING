"""Pins for the audit 2026-09-26 fixes - what each fix must keep doing.

test_audit_20260926.py states the defects. This file states the edges each
fix had to get right, found by running them, so that a later "simplification"
fails here instead of reopening the class:

  R3    the obvious fix (copy2 follow_symlinks=False) loses the content of a
        write THROUGH a relative link and still reports REVERSIBLE.
  R4    the workspace is skipped by PATH; the syscall guard had the same
        name-based skip.
  DIFF  the live tree is filtered only where the capture does not hold the dir.
  LOG   "missing" and 0B are different answers.
  cp    the vote is necessary: without it `DROP TABLE t; cp -f a b` snapshots
        b and calls the whole line REVERSIBLE.
  QUOTE eleven forms pass CODE through a quoted argument and are caught only
        because rm_rf ignores quotes. Releasing prose must not release them.
  S3    the git pre-filter globs are generated from the git rules.

Every negative assertion here has a control that must pass first.
"""
import os
import sys
import tempfile

import pytest

from demo_cli import checkpoint, recovery, render
from demo_cli import diff as diff_mod
from demo_cli.classify import (POSIX, _DESTRUCTIVE, classify_pipeline,
                               git_prefilter_globs, required_literals)
from demo_cli.cli import _SHELL_GUARD_SNIPPET
from demo_cli.config import Config
from demo_cli.guard import Guard


def _symlinks_available() -> bool:
    with tempfile.TemporaryDirectory() as d:
        try:
            os.symlink(os.path.join(d, "t"), os.path.join(d, "l"))
            return True
        except (OSError, NotImplementedError, AttributeError):
            return False


requires_symlinks = pytest.mark.skipif(
    not _symlinks_available(), reason="creating a symlink needs privilege here")


@pytest.fixture()
def proj(tmp_path, monkeypatch):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    p = tmp_path / "proj"
    p.mkdir()
    monkeypatch.chdir(p)
    return p


def _guard(root):
    return Guard(Config(project_root=str(root)), mode="enforce")


# ==========================================================================
# R3 - a symlink is captured as its bytes AND its link
# ==========================================================================

@requires_symlinks
def test_a_write_through_a_relative_link_is_undone(proj):
    """`echo x > link` truncates the TARGET. copy2(follow_symlinks=False)
    kept only the relative link, which dangles inside the recovery store:
    REVERSIBLE was reported and undo returned False with the content gone."""
    (proj / "real.txt").write_text("REAL CONTENT")
    os.symlink("real.txt", proj / "link.txt")
    r = _guard(proj).evaluate("echo x > link.txt")
    assert r.decision.decision == "REVERSIBLE"

    (proj / "link.txt").write_text("x\n")                 # through the link
    assert (proj / "real.txt").read_text() == "x\n", "precondition"
    assert recovery.restore_entry(r.recovery_entry) is True
    assert (proj / "real.txt").read_text() == "REAL CONTENT"
    assert os.path.islink(proj / "link.txt")


@requires_symlinks
def test_a_replaced_relative_link_comes_back_as_the_same_link(proj):
    (proj / "real.txt").write_text("REAL CONTENT")
    os.symlink("real.txt", proj / "link.txt")
    r = _guard(proj).evaluate_file_edit(str(proj / "link.txt"), tool_name="Write")
    os.remove(proj / "link.txt")
    (proj / "link.txt").write_text("CLOBBERED")

    assert recovery.restore_entry(r.recovery_entry) is True
    assert os.readlink(proj / "link.txt") == "real.txt", \
        "restored as a link, but not the one that was there"


def test_an_ordinary_file_entry_carries_no_link(proj):
    """Control for the two above: the link field appears only for links."""
    (proj / "plain.txt").write_text("x")
    r = _guard(proj).evaluate_file_edit(str(proj / "plain.txt"), tool_name="Write")
    assert r.recovery_entry and "link" not in r.recovery_entry


# ==========================================================================
# LOG-0B - "missing" is not 0B
# ==========================================================================

def test_log_says_missing_for_a_point_that_is_gone(proj, capsys):
    rec = str(proj / ".demo_cli" / "recovery")
    (proj / "empty.txt").write_text("")
    empty = recovery.snapshot(recovery.Target("file", str(proj / "empty.txt"),
                                              "empty"), rec, "snapshot")
    gone = dict(empty, id="deadbeef", recovery_point=str(proj / "nowhere.bak"))
    render.set_color(False)
    render.render_log([empty, gone], "test")
    out = capsys.readouterr().out
    row = {line.split()[0]: line for line in out.splitlines()
           if line.strip().startswith((empty["id"][:8], "deadbeef"))}
    assert "0B" in row[empty["id"][:8]], "control: an empty point is 0B"
    assert "missing" in row["deadbeef"] and "0B" not in row["deadbeef"]


def test_prune_counts_a_missing_point_as_nothing_freed(proj):
    rec = str(proj / ".demo_cli" / "recovery")
    (proj / "a.txt").write_text("abc")
    e = recovery.snapshot(recovery.Target("file", str(proj / "a.txt"), "a"),
                          rec, "snapshot")
    os.remove(e["recovery_point"])
    removed = recovery.prune(rec, keep=0)
    assert [x["_freed_bytes"] for x in removed] == [0]


# ==========================================================================
# R4 - the workspace is skipped by path, everywhere
# ==========================================================================

@pytest.mark.skipif(sys.platform != "linux", reason="syscall guard is Linux-only")
def test_syscall_scope_skips_the_workspace_by_path(tmp_path):
    from demo_cli import syscall_guard
    root = str(tmp_path)
    ws = os.path.join(root, ".demo_cli")
    assert not syscall_guard._in_scope(os.path.join(root, ".git", "config"), root, ws), \
        "control: a name-ignored directory is still out of scope"
    assert not syscall_guard._in_scope(os.path.join(ws, "receipts.jsonl"), root, ws)
    assert syscall_guard._in_scope(
        os.path.join(root, "payload", ".demo_cli", "user_data.txt"), root, ws), \
        "a user directory that shares the workspace's name was out of scope"


def test_a_checkpoint_never_copies_a_custom_workspace(tmp_path):
    """Name-based skipping only knew `.demo_cli`. A workspace configured under
    any other name was copied into the checkpoint - ledger included - and an
    undo of that checkpoint would overlay the old ledger on the new one."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("code")
    cfg = Config(project_root=str(tmp_path), workspace_dir="state",
                 checkpoint={"enabled": True})
    os.makedirs(cfg.recovery_dir)
    with open(cfg.receipts_path, "w") as f:
        f.write('{"receipt": 1}\n')
    res = checkpoint.capture(cfg, "rm $T")
    assert res.entry, res.skipped
    held = os.listdir(res.entry["recovery_point"])
    assert "src" in held, "control: the project itself was captured"
    assert "state" not in held, "the workspace was copied into its own checkpoint"


# ==========================================================================
# DIFF - the live side is filtered only where the capture holds nothing
# ==========================================================================

def test_diff_reports_a_change_inside_a_captured_git(proj):
    sub = proj / "sub"
    (sub / ".git").mkdir(parents=True)
    (sub / ".git" / "HEAD").write_text("ref: refs/heads/main")
    (sub / "code.py").write_text("print(1)")
    r = _guard(proj).evaluate(f"rm -rf {sub}")
    snap = r.recovery_entry["recovery_point"]

    (sub / ".git" / "HEAD").write_text("ref: refs/heads/other")
    (sub / "node_modules").mkdir()
    (sub / "node_modules" / "x.js").write_text("dep")
    text = [d.text for d in diff_mod.diff_dir(snap, str(sub))]
    assert f"{os.path.join('.git', 'HEAD')}: modified" in text, text
    assert not any(t.startswith("node_modules") for t in text), (
        "a directory the capture never held is still ignored on the live side")


# ==========================================================================
# cp - an overwrite of something that exists, and only that
# ==========================================================================

@pytest.mark.parametrize("cmd,expected", [
    ("cp -f a.txt b.txt", "REVERSIBLE"),
    ("cp a.txt b.txt", "REVERSIBLE"),          # -f changes nothing here
    ("cp a.txt dest/", "REVERSIBLE"),          # dest/a.txt exists
    ("cp -t dest a.txt", "REVERSIBLE"),
    ("cp a.txt new.txt", "ALLOW"),             # creates; destroys nothing
    ("cp -n a.txt b.txt", "ALLOW"),            # never overwrites
    ("cp --no-clobber a.txt b.txt", "ALLOW"),
])
def test_cp_is_judged_by_its_destination(proj, cmd, expected):
    (proj / "a.txt").write_text("SOURCE")
    (proj / "b.txt").write_text("ORIGINAL")
    (proj / "dest").mkdir()
    (proj / "dest" / "a.txt").write_text("OLD")
    r = _guard(proj).evaluate(cmd)
    assert r.decision.decision == expected, (cmd, r.decision.reason)
    assert bool(r.recovery_entry) == (expected == "REVERSIBLE"), cmd


@pytest.mark.parametrize("first", [
    "sqlite3 x.db 'DROP TABLE t'",
    "git reset --hard",
])
def test_cp_votes_when_another_segment_also_destroys(proj, first):
    """Without the vote each of these snapshotted b.txt and reported the whole
    line REVERSIBLE (measured). The control shows the cp alone IS covered, so
    the escalation is about the second destruction, not about cp."""
    (proj / "a.txt").write_text("SOURCE")
    (proj / "b.txt").write_text("ORIGINAL")
    g = _guard(proj)
    assert g.evaluate("cp -f a.txt b.txt").decision.decision == "REVERSIBLE", "control"
    r = g.evaluate(f"{first}; cp -f a.txt b.txt")
    assert r.decision.decision == "ESCALATE", r.decision.reason
    assert not r.recovery_entry


def test_cp_undo_puts_the_original_back(proj):
    (proj / "a.txt").write_text("SOURCE")
    (proj / "b.txt").write_text("ORIGINAL")
    r = _guard(proj).evaluate("cp a.txt b.txt")
    (proj / "b.txt").write_text("SOURCE")                 # what cp does
    assert recovery.restore_entry(r.recovery_entry) is True
    assert (proj / "b.txt").read_text() == "ORIGINAL"


def test_the_preview_names_what_cp_overwrites(proj):
    (proj / "a.txt").write_text("SOURCE")
    (proj / "b.txt").write_text("ORIGINAL")
    r = _guard(proj).evaluate("cp a.txt b.txt")
    assert r.affected_paths == [str(proj / "b.txt")]


# ==========================================================================
# QUOTE / O1 / O2 - prose is released, quoted CODE is not
# ==========================================================================

STILL_CAUGHT = [
    "sudo sh -c 'rm -rf build'",
    "echo 'rm -rf build' | sh",
    'echo "rm -rf x" | bash',
    "bash -c \"echo 'rm -rf x'\" | sh",
    "ssh host 'rm -rf /data'",
    "su -c 'rm -rf build'",
    "docker exec c sh -c 'rm -rf /data'",
    "xargs sh -c 'rm -rf build'",
    "find . -exec sh -c 'rm -rf \"$1\"' _ {} \\;",
    "watch 'rm -rf build'",
    'git commit -m "$(rm -rf build)"',
    "trap 'rm -rf build' EXIT",
    "printf 'DROP TABLE users;' | psql",
    "rg --pre 'rm -rf x' pattern",
    "echo it\\'s; rm -rf build",
    'echo \\"; rm -rf build; echo "',
    # heredocs whose consumer RUNS the body
    "bash <<'EOF'\nrm -rf build\nEOF",
    "psql <<'EOF'\nDROP TABLE users;\nEOF",
    "ssh host <<'EOF'\nrm -rf /data\nEOF",
    "cat <<'EOF' | sh\nrm -rf build\nEOF",
    "cat <<EOF > f\n$(rm -rf build)\nEOF",
    # --help that is not the only thing after the verb
    "rm -rf build --help",
    "curl -X DELETE https://api.example.com/u/1 -H --help",
    "curl -X DELETE --help https://api.example.com/u/1",
]


@pytest.mark.parametrize("cmd", STILL_CAUGHT)
def test_quoted_code_is_still_caught(cmd):
    r = classify_pipeline(cmd)
    assert r.needs_recovery or r.remote_exec, (cmd, r.segments)


def test_a_segment_after_a_heredoc_still_counts(proj):
    """The body is skipped; the command after the terminator is not."""
    r = classify_pipeline("cat <<'EOF' > notes.md\ngit push --force\nEOF\nrm -rf build")
    assert r.destructive_segments == 2, r.segments        # the redirect + rm
    assert r.nonrecoverable_surface is None, "the body was judged as a command"


def test_a_heredoc_written_to_a_new_file_is_allowed(proj):
    r = _guard(proj).evaluate("cat <<'EOF' > notes.md\ngit push --force origin main\nEOF")
    assert r.decision.decision == "ALLOW", r.decision.reason


# ==========================================================================
# S3 - the git pre-filter is derived from the git rules
# ==========================================================================

def _git_rules():
    return [(rid, rx) for rid, t, rx, only in _DESTRUCTIVE
            if t == "git" and only in (None, POSIX)]


def test_every_git_rule_requires_some_literal():
    """An empty chain would become `**` - a glob that submits everything."""
    for rid, rx in _git_rules():
        chains = required_literals(rx.pattern)
        assert chains and all(chains), rid


def test_the_snippet_carries_exactly_the_generated_git_globs():
    globs = git_prefilter_globs()
    assert len(globs) >= len(_git_rules())
    for g in globs:
        assert g in _SHELL_GUARD_SNIPPET, g
    assert "*git\\ *" not in _SHELL_GUARD_SNIPPET, "the catch-all is back"


GIT_DESTRUCTIVE = [
    "git push --force origin main", "git push -f", "git reset --hard HEAD~1",
    "git clean -fd", "git worktree remove --force wt", "git branch -D feature",
    "git branch --delete --force feat", "git checkout -- src/app.py",
    "git checkout .", "git restore config.py", "git stash drop",
    "git stash pop", "git stash clear", "git reflog expire --expire=now --all",
    "git gc --prune=now", "git filter-branch --tree-filter x",
    "git filter-repo --path x", "git update-ref -d refs/heads/x",
]


def _harness():
    from test_audit_20260926 import BASH, BLOCKS, RECORDS, _run_guarded
    return BASH, BLOCKS, RECORDS, _run_guarded


@pytest.mark.parametrize("cmd", GIT_DESTRUCTIVE)
def test_every_destructive_git_command_reaches_the_guard(tmp_path, cmd):
    """Live DEBUG trap. BLOCKS, so none of these ever runs."""
    BASH, BLOCKS, _, run = _harness()
    if BASH is None:
        pytest.skip("no bash for this platform")
    assert classify_pipeline(cmd).is_destructive, f"precondition: {cmd}"
    _r, seen = run(tmp_path, BLOCKS, cmd)
    assert any("guard-shell" in c and cmd in c for c in seen), (
        f"{cmd!r} is destructive and the pre-filter dropped it")


@pytest.mark.parametrize("cmd", [
    "git status", "git log --oneline -1", "git diff", "git branch",
    "git branch --list", "git show", "git remote -v", "git stash list",
])
def test_git_reads_stay_in_bash(tmp_path, cmd):
    BASH, _, RECORDS, run = _harness()
    if BASH is None:
        pytest.skip("no bash for this platform")
    (tmp_path / "control.txt").write_text("c")
    _r, seen = run(tmp_path, RECORDS, f"rm -f control.txt; {cmd}")
    assert any("control.txt" in c for c in seen), \
        "harness precondition failed: the stub was never reached"
    assert not any(cmd in c for c in seen), f"{cmd!r} spawned the guard"


# ==========================================================================
# Round 2 (2026-09-26): the command word is not always first
#
# Every rule anchored to the start of a segment - rm_local, the container,
# datastore and registry surfaces, the PowerShell cmdlets - and target
# resolution with them, missed a command behind a keyword or a wrapper. Each
# row below was ALLOW with nothing captured before this change.
# ==========================================================================

from demo_cli.classify import POWERSHELL, command_position  # noqa: E402

BEHIND_A_KEYWORD_OR_WRAPPER = [
    ("for c in a b; do docker rm -f $c; done", POSIX),
    ("if true; then docker volume rm v; fi", POSIX),
    ("{ docker volume rm v; }", POSIX),
    ("( docker volume rm v )", POSIX),
    ("time docker volume rm v", POSIX),
    ("env docker volume rm v", POSIX),
    ("nohup docker system prune -af", POSIX),
    ("timeout 60 docker volume rm v", POSIX),
    ("sudo -u root docker volume rm v", POSIX),
    ("nice -n 10 redis-cli FLUSHALL", POSIX),
    ("command npm unpublish p@1", POSIX),
    ("for f in a b; do rm $f; done", POSIX),
    ("while read f; do rm \"$f\"; done < list", POSIX),
    ("find . -name '*.pyc' | xargs rm", POSIX),
    ("xargs -I{} rm {}", POSIX),
    ("! rm x.txt", POSIX),
    ("find . -name '*.tmp' -exec rm {} \\;", POSIX),
    ("Get-ChildItem *.log | ForEach-Object { Remove-Item $_ }", POWERSHELL),
    ("gci *.log | % { ri $_ }", POWERSHELL),
    ("if (Remove-Item x -Recurse -Force) { }", POWERSHELL),
]


@pytest.mark.parametrize("cmd,dialect", BEHIND_A_KEYWORD_OR_WRAPPER)
def test_a_command_behind_a_keyword_or_wrapper_is_judged(cmd, dialect):
    r = classify_pipeline(cmd, dialect)
    assert r.needs_recovery, (cmd, r.segments)


@pytest.mark.parametrize("cmd", [
    "command -v rm",          # a lookup, not an execution
    "command -V docker",
    "type rm",
    "echo if then rm",        # the words are arguments here
    "sudo -l", "time", "env", "(( i++ ))",
    "find . -name '*.tmp' -print",
])
def test_the_normalizer_invents_nothing(cmd):
    assert not classify_pipeline(cmd).needs_recovery, cmd


@pytest.mark.parametrize("cmd", [
    "timeout $(rm -rf x) ls",
    "A=$(rm -rf x) ls",
    "sudo -u `rm -rf x` ls",
])
def test_the_normalizer_never_strips_code(cmd):
    """A token that can carry code stops the walk; the segment stays whole,
    so the unanchored rule still sees the rm inside it."""
    assert command_position(cmd) == [cmd]
    assert classify_pipeline(cmd).matched_rule == "rm_rf", cmd


@pytest.mark.parametrize("cmd", [
    "sudo -u root rm x.txt",
    "if true; then rm x.txt; fi",
    "( rm x.txt )",
    "nohup rm x.txt",
])
def test_the_target_behind_a_wrapper_is_resolved_and_captured(proj, cmd):
    (proj / "x.txt").write_text("keep")
    r = _guard(proj).evaluate(cmd)
    assert r.decision.decision == "REVERSIBLE", (cmd, r.decision.reason)
    assert r.target and r.target.ref == str(proj / "x.txt")


def test_an_unresolvable_loop_variable_escalates(proj):
    r = _guard(proj).evaluate("for f in a b; do rm $f; done")
    assert r.decision.decision == "ESCALATE" and not r.recovery_entry


# ==========================================================================
# Round 2: in-place editors, and the writer vote
# ==========================================================================

@pytest.mark.parametrize("cmd,expected", [
    ("sed -i 's/a/b/' f.txt", "REVERSIBLE"),
    ("sed -ie 's/a/b/' f.txt", "REVERSIBLE"),        # -i with suffix "e"
    ("sed --in-place=.bak s/a/b/ f.txt", "REVERSIBLE"),
    ("sed -i.bak -e 's/a/b/' f.txt", "REVERSIBLE"),
    ("perl -pi -e 's/a/b/' f.txt", "REVERSIBLE"),
    ("perl -i.bak -pe 's/a/b/' f.txt", "REVERSIBLE"),
    ("sed 's/a/b/' f.txt", "ALLOW"),                 # no -i: prints only
    ("sed -n p f.txt", "ALLOW"),
    ("perl -ne 'print' f.txt", "ALLOW"),
    ("perl script.pl f.txt", "ALLOW"),
    ("sed -i s/a/b/ missing.txt", "ALLOW"),          # nothing there to lose
])
def test_in_place_editors_are_judged_by_their_files(proj, cmd, expected):
    (proj / "f.txt").write_text("abc")
    r = _guard(proj).evaluate(cmd)
    assert r.decision.decision == expected, (cmd, r.decision.reason)
    if r.recovery_entry:
        assert r.target.ref == str(proj / "f.txt")


def test_sed_undo_puts_the_original_back(proj):
    (proj / "f.txt").write_text("abc")
    r = _guard(proj).evaluate("sed -i 's/a/X/' f.txt")
    (proj / "f.txt").write_text("Xbc")
    assert recovery.restore_entry(r.recovery_entry) is True
    assert (proj / "f.txt").read_text() == "abc"


@pytest.mark.parametrize("cmd", [
    "sqlite3 x.db 'DROP TABLE t'; prettier --write f.js",
    "git reset --hard; prettier --write f.js",
    "git reset --hard; sed -i s/a/b/ f.js",
    "rm old.txt && sed -i s/a/b/ f.js",
])
def test_a_writer_votes_like_any_other_destruction(proj, cmd):
    """Measured REVERSIBLE before (the first two): f.js was captured and the
    receipt claimed the line, table and hard reset included."""
    (proj / "f.js").write_text("x")
    (proj / "old.txt").write_text("o")
    g = _guard(proj)
    assert g.evaluate("prettier --write f.js").decision.decision == "REVERSIBLE", "control"
    r = g.evaluate(cmd)
    if "git reset" in cmd or "DROP TABLE" in cmd:
        assert r.decision.decision == "ESCALATE", (cmd, r.decision.reason)
        assert not r.recovery_entry
    else:
        expected = "REVERSIBLE" if ENGINE_PATH else "ESCALATE"
        assert r.decision.decision == expected, (cmd, r.decision.reason)
        if ENGINE_PATH:
            assert_restores(r.recovery_entry, proj, {"old.txt": b"o", "f.js": b"x"})


@pytest.mark.parametrize("cmd", [
    "sed -i 's/a/b/' f.txt", "sed -ni 's/a/b/p' f.txt", "perl -pi -e 's/a/b/' f.txt",
    "printf 'a\\n' | xargs rm",
])
def test_the_shell_guard_submits_in_place_edits(tmp_path, cmd):
    BASH, BLOCKS, _, run = _harness()
    if BASH is None:
        pytest.skip("no bash for this platform")
    _r, seen = run(tmp_path, BLOCKS, cmd)
    last = cmd.split("|")[-1].strip()
    assert any("guard-shell" in c and last in c for c in seen), (
        f"{cmd!r} never reached the guard")


# ==========================================================================
# Round 3 (review 2026-09-27): one question, one answer
#
# Three of these four were two parsers answering the same question
# differently; the fourth is a scope rule that read the path instead of
# where the bytes live.
# ==========================================================================

def test_cp_sources_resolve_from_the_cd_directory(proj):
    """The destination followed the `cd`; the source glob did not, matched
    nothing, and the overwrite of sub/dest/a.txt went unseen (ALLOW)."""
    (proj / "sub" / "dest").mkdir(parents=True)
    (proj / "sub" / "a.txt").write_text("A")
    (proj / "sub" / "dest" / "a.txt").write_text("OLD")
    g = _guard(proj)
    assert g.evaluate("cp sub/*.txt sub/dest/").target.ref == \
        str(proj / "sub" / "dest" / "a.txt"), "control: without the cd"
    r = g.evaluate("cd sub && cp *.txt dest/")
    assert r.decision.decision == "REVERSIBLE", r.decision.reason
    assert r.target.ref == str(proj / "sub" / "dest" / "a.txt")


@requires_symlinks
def test_a_link_out_of_the_project_is_not_captured(proj, tmp_path):
    """Scope is decided by where the bytes live. The link's path is inside
    the project; its content was copied into the project's store and undo
    would have written outside it."""
    (tmp_path / "secret.txt").write_text("SECRET")
    os.symlink(str(tmp_path / "secret.txt"), proj / "innocent.txt")
    (proj / "inside.txt").write_text("IN")
    os.symlink("inside.txt", proj / "ok_link.txt")
    g = _guard(proj)
    assert g.evaluate_file_edit(str(proj / "ok_link.txt"), tool_name="Write") \
        .decision.decision == "REVERSIBLE", "control: a link inside is still covered"

    r = g.evaluate_file_edit(str(proj / "innocent.txt"), tool_name="Write")
    assert r.decision.decision == "ESCALATE" and not r.recovery_entry
    assert "links to" in r.decision.reason, r.decision.reason
    r = g.evaluate("echo x > innocent.txt")
    assert r.decision.decision == "ESCALATE" and not r.recovery_entry

    store = Config(project_root=str(proj)).recovery_dir
    leaked = [f for f in (os.listdir(store) if os.path.isdir(store) else [])
              if "SECRET" in open(os.path.join(store, f), errors="ignore").read()]
    assert leaked == [], f"outside content copied into the store: {leaked}"


@requires_symlinks
@pytest.mark.skipif(sys.platform != "linux", reason="syscall guard is Linux-only")
def test_syscall_scope_follows_links(tmp_path):
    from demo_cli import syscall_guard
    root = tmp_path / "proj"
    root.mkdir()
    (root / "in.txt").write_text("i")
    (tmp_path / "out.txt").write_text("o")
    os.symlink(str(tmp_path / "out.txt"), root / "l")
    assert syscall_guard._in_scope(str(root / "in.txt"), str(root)), "control"
    assert not syscall_guard._in_scope(str(root / "l"), str(root))


@pytest.mark.parametrize("prefix", ["", "nohup ", "sudo -u me ", "env X=1 "])
def test_a_heredoc_behind_a_wrapper_is_judged_by_its_command(prefix):
    body = "\ngit push --force origin main\nEOF"
    assert classify_pipeline(f"{prefix}bash <<'EOF'{body}").nonrecoverable_surface \
        == "remote_vcs_history", "control: a body that runs is still judged"
    assert classify_pipeline(f"{prefix}cat <<'EOF' > n.md{body}") \
        .nonrecoverable_surface is None, "a data body behind a wrapper was run"


def test_help_is_not_a_write_on_either_path(proj):
    """The classifier released --help, target resolution did not, so the
    phantom writer was a second destructive step."""
    (proj / "x.txt").write_text("x")
    (proj / "f.py").write_text("x = 1")
    g = _guard(proj)
    expected = "REVERSIBLE" if ENGINE_PATH else "ESCALATE"
    r_ctrl = g.evaluate("black f.py && rm x.txt")
    assert r_ctrl.decision.decision == expected, "control: a real write IS a second step"
    if ENGINE_PATH:
        assert_restores(r_ctrl.recovery_entry, proj, {"f.py": b"x = 1", "x.txt": b"x"})
    r = g.evaluate("black --help && rm x.txt")
    assert r.decision.decision == "REVERSIBLE", r.decision.reason
