"""Audit 2026-09-26: eighteen defects confirmed live at f694dba (v1.7.0).

Every test here FAILS on the commit that introduced this file. That is the
point: the suite was green at 826 passing while all eighteen were reachable,
so nothing in it described these behaviours. Each test states the behaviour
demo_cli claims to have, so a fix has something to turn green and a
regression has something to break.

Grouped by what the defect costs:

  Tier 1  the tool reports a recovery it did not take   (R2 R4 R3 cp-f DIFF LOG-0B)
  Tier 2  the guard is absent, bypassable or unrecorded (S1 S4 S5 KILL ASYM EGRESS)
  Tier 3  text is judged as if it were a command        (QUOTE O1 O2), plus cost
          (DOUBLE-FIRE S3 S2)

Two defects from the audit are NOT here: ELEV-MSG and ORPHAN need Windows and
were left unverified rather than guessed at.

WHERE THIS OVERLAPS EXISTING TESTS, DELIBERATELY:

  * test_symlink_snapshot.py pins `copytree(symlinks=True)` - the DIRECTORY
    branch. R3 below is the FILE branch, `copy2(ref, bak)` at recovery.py:338,
    which that file never reaches. The fix there was real and incomplete.

  * test_ignored_dir_capture.py asserts, on purpose, that `.demo_cli` is never
    un-ignored: un-ignoring it would copy the backup into the backup. R4 below
    must therefore NOT be fixed by un-ignoring the name. It must be fixed by
    telling the workspace PATH apart from a directory that merely shares its
    name. The existing test is kept honest by test_r4_the_real_workspace_is_
    still_ignored, which asserts the rule it protects.

  * test_shell_guard.py::test_the_kill_switch_turns_the_guard_off passes
    DEMO_CLI_DISABLE=1 into a NEW shell, where the top-level `if` sees it and
    the trap is never installed. Its docstring claims this "still works from a
    shell that is otherwise stuck". It does not - that is KILL below.
"""
import json
import os
import shutil
import socket
import subprocess
import tempfile

import pytest

from demo_cli import recovery
from demo_cli.classify import classify_pipeline
from demo_cli.cli import _SHELL_GUARD_SNIPPET
from demo_cli.config import Config
from demo_cli.guard import Guard
from demo_cli.hooks.claude_code import install_into_settings
from demo_cli.lifecycle import _strip_hook_entries

BASH = shutil.which("bash")
requires_bash = pytest.mark.skipif(BASH is None, reason="no bash on this platform")


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
    monkeypatch.chdir(tmp_path)
    return p


# ==========================================================================
# Tier 1 - the tool reports a recovery it did not take
# ==========================================================================

def test_r2_a_file_edit_outside_the_project_is_not_called_reversible(proj, tmp_path):
    """R2 - guard.py:542. evaluate_file_edit abspath()s its argument and never
    compares it to project_root, so the Edit/Write door snapshots and blesses
    any path on the machine. The shell door refuses the identical path at
    guard.py:302. Two doors, one project, opposite answers."""
    outside = tmp_path.parent / "outside_victim.txt"
    outside.write_text("precious")
    g = Guard(Config(project_root=str(proj)), mode="enforce")

    r = g.evaluate_file_edit(str(outside), tool_name="Write")
    assert r.decision.decision != "REVERSIBLE", (
        "a Write outside the project root was called reversible; "
        "the shell door escalates on the same path")


def test_r2_the_project_root_itself_is_not_a_file_edit_target(proj):
    """R2, second shape. guard.py:307 already refuses the project root as a
    capture surface for the shell door, with a comment explaining why. The
    file-edit door has no such refusal."""
    g = Guard(Config(project_root=str(proj)), mode="enforce")
    r = g.evaluate_file_edit(str(proj), tool_name="Write")
    assert r.decision.decision != "REVERSIBLE", \
        "the project root itself was accepted as a reversible file edit"


def test_r2_a_home_dotfile_is_not_snapshotted_into_the_project(proj):
    """R2, the consequence that is not only a wrong label: the file is COPIED
    into the project's recovery directory. Pointed at /etc/hosts or an ssh
    config, the honesty bug is also an exfiltration bug."""
    g = Guard(Config(project_root=str(proj)), mode="enforce")
    victim = os.path.join(os.path.expanduser("~"), ".bashrc")
    if not os.path.isfile(victim):
        pytest.skip("no ~/.bashrc on this machine")
    r = g.evaluate_file_edit(victim, tool_name="Write")
    assert not r.recovery_entry, \
        "a file from $HOME was copied into the project's recovery store"


@requires_symlinks
def test_r3_a_snapshotted_symlink_is_still_a_symlink_after_undo(proj):
    """R3 - recovery.py:338. The FILE branch calls shutil.copy2(ref, bak) with
    no follow_symlinks=False, so the snapshot holds the target's BYTES. Undo
    then writes those bytes back as a regular file and the link is gone.

    test_symlink_snapshot.py fixed exactly this for the directory branch and
    said why: "rm link destroys the link, not its target, so restoring a link
    is correct and restoring a regular file full of the target's bytes never
    was." The file branch never got the same treatment."""
    real = proj / "real_target.txt"
    real.write_text("REAL CONTENT")
    link = proj / "link.txt"
    os.symlink(str(real), str(link))

    g = Guard(Config(project_root=str(proj)), mode="enforce")
    r = g.evaluate_file_edit(str(link), tool_name="Write")
    assert r.recovery_entry, "no snapshot was taken for an existing link"

    os.remove(str(link))
    link.write_text("CLOBBERED")
    assert recovery.restore_entry(r.recovery_entry) is True
    assert os.path.islink(str(link)), \
        "undo replaced the symlink with a plain copy of its target"


def test_r4_a_decoy_dot_demo_cli_directory_is_captured(proj):
    """R4 - recovery.py:349 + targets.py:48. IGNORED_DIRS is matched by NAME,
    so ANY directory called .demo_cli is dropped from a directory capture -
    including one full of a user's own files that has nothing to do with the
    workspace. The entry is still recorded and the decision is still
    REVERSIBLE, which is the part that makes it a lie rather than a limit.

    THE FIX MUST NOT BE to un-ignore the name: see the companion test below."""
    payload = proj / "payload"
    (payload / ".demo_cli").mkdir(parents=True)
    (payload / ".demo_cli" / "user_data.txt").write_text("NOT THE WORKSPACE")
    (payload / "keep.txt").write_text("ordinary")

    rec = str(proj / ".demo_cli" / "recovery")
    entry = recovery.snapshot(recovery.Target("dir", str(payload), str(payload)),
                              rec, "snapshot", action="rm -rf payload")
    assert entry, "no snapshot was taken"
    held = os.listdir(entry["recovery_point"])
    assert ".demo_cli" in held, (
        f"a user directory named .demo_cli was omitted from a capture "
        f"reported as complete; captured only {sorted(held)}")


def test_r4_the_real_workspace_is_still_ignored(proj):
    """The capability R4's fix must not cost, and the reason the obvious fix is
    wrong. Copying the recovery store into the recovery store is the bug
    test_ignored_dir_capture.py::test_the_recovery_store_is_never_un_ignored
    exists to prevent. This passes today and must keep passing."""
    rec = str(proj / ".demo_cli" / "recovery")
    os.makedirs(rec, exist_ok=True)
    (proj / "src").mkdir()
    (proj / "src" / "a.py").write_text("code")

    entry = recovery.snapshot(recovery.Target("dir", str(proj), str(proj)),
                              rec, "snapshot", action="rm -rf proj")
    assert entry
    held = os.listdir(entry["recovery_point"])
    assert ".demo_cli" not in held, \
        "the recovery store was copied into itself"


def test_cp_f_overwriting_an_existing_file_is_snapshotted(proj):
    """cp-f - classify.py:62-205 has no cp rule at all, so `cp -f a b` is
    "Non-mutating action; outside the invariant" and b is overwritten with no
    recovery point. A truncating redirect to the same file IS caught
    (fs_redirect_truncate); cp reaches the same end by another verb."""
    (proj / "a.txt").write_text("SOURCE")
    (proj / "b.txt").write_text("ORIGINAL - must be recoverable")
    g = Guard(Config(project_root=str(proj)), mode="enforce")
    r = g.evaluate("cp -f a.txt b.txt")
    assert r.recovery_entry, (
        "cp -f overwrote an existing file with no snapshot "
        f"(decision was {r.decision.decision}: {r.decision.reason})")


def test_diff_shows_an_ignored_directory_that_the_capture_holds(proj):
    """DIFF - diff.py:106. The capture lift works: when a command destroys a
    parent holding .git, unignorable_dirs lifts the ignore and .git IS copied.
    _manifest() then filters IGNORED_DIRS from BOTH sides, so `demo_cli diff`
    renders that capture as though it had no .git - in front of the person
    deciding whether to undo."""
    from demo_cli import diff as diff_mod
    sub = proj / "sub"
    (sub / ".git").mkdir(parents=True)
    (sub / ".git" / "HEAD").write_text("ref: refs/heads/main")
    (sub / "code.py").write_text("print(1)")

    g = Guard(Config(project_root=str(proj)), mode="enforce")
    r = g.evaluate(f"rm -rf {sub}")
    assert r.recovery_entry, "no capture to diff"
    snap = r.recovery_entry["recovery_point"]
    assert os.path.isdir(os.path.join(snap, ".git")), \
        "precondition: the capture should hold .git"

    manifest = diff_mod._manifest(snap)
    assert any(k.startswith(".git") for k in manifest), (
        f"the capture holds .git but the diff hides it; diff sees "
        f"{sorted(manifest)}")


def test_log_tells_unreadable_apart_from_empty(proj):
    """LOG-0B - recovery.py:544. entry_size() returns 0 both for "this recovery
    point is zero bytes" and for "I cannot stat it", and `log` renders both as
    0B under a footer offering `undo <id>`. The README has listed this under
    Known issues since the beta; it is still true.

    "0 bytes" and "I cannot see it" are different facts. This test only asks
    that they be distinguishable - it does not prescribe the rendering."""
    f = proj / "data.txt"
    f.write_text("X" * 4000)
    rec = str(proj / ".demo_cli" / "recovery")
    entry = recovery.snapshot(recovery.Target("file", str(f), str(f)),
                              rec, "snapshot", action="edit data.txt")
    assert recovery.entry_size(entry) == 4000

    empty = proj / "empty.txt"
    empty.write_text("")
    empty_entry = recovery.snapshot(recovery.Target("file", str(empty), str(empty)),
                                    rec, "snapshot", action="edit empty.txt")
    assert recovery.entry_size(empty_entry) == 0

    entry["recovery_point"] = str(proj / "gone" / "vanished.bak")
    unreadable = recovery.entry_size(entry)
    assert unreadable != 0, (
        "an unreadable recovery point reports the same 0 as a genuinely "
        "empty one; `log` renders both as 0B and still offers undo")


# ==========================================================================
# Tier 2 - the guard is absent, bypassable, or leaves no record
# ==========================================================================

def _run_guarded(tmp_path, stub_body, command, env_extra=None, preload=True):
    """A real bash, the real snippet, and a stub demo_cli that records calls.

    `preload=False` keeps the stub OFF the PATH at snippet-load time, which is
    how S5 is reproduced.
    """
    binn = tmp_path / "bin"
    binn.mkdir(exist_ok=True)
    calls = tmp_path / "calls.log"
    stub = binn / "demo_cli"
    stub.write_text(stub_body.replace("@CALLS@", str(calls)), newline="\n")
    stub.chmod(0o755)

    script = tmp_path / "guard.sh"
    script.write_text(_SHELL_GUARD_SNIPPET, newline="\n")

    env = dict(os.environ)
    env.pop("DEMO_CLI_DISABLE", None)
    # preload=False must mean NO demo_cli resolvable at snippet-load time. The
    # ambient PATH carries a real pipx install, which silently turned the S5
    # test green by satisfying the very `command -v` it is meant to catch.
    base = env["PATH"] if preload else os.pathsep.join(["/usr/bin", "/bin"])
    env["PATH"] = f"{binn}{os.pathsep}{base}" if preload else base
    env["BASH_ENV"] = str(script)
    env.update(env_extra or {})
    r = subprocess.run([BASH, "-c", command], capture_output=True, text=True,
                       env=env, timeout=60, cwd=str(tmp_path))
    seen = calls.read_text().splitlines() if calls.exists() else []
    return r, seen


RECORDS = ('#!/bin/sh\n'
           'if [ "$1" = "--version" ]; then echo 1.7.0; exit 0; fi\n'
           'echo "$@" >> @CALLS@\n'
           'exit 0\n')
BROKEN = '#!/bin/sh\necho "SyntaxError: broken" >&2\nexit 1\n'
BLOCKS = ('#!/bin/sh\n'
          'if [ "$1" = "--version" ]; then echo 1.7.0; exit 0; fi\n'
          'echo "$@" >> @CALLS@\n'
          'exit 1\n')


@requires_bash
@pytest.mark.parametrize("command,rule", [
    ("mv keep.txt moved.txt", "mv_overwrite"),
    ("dd if=/dev/zero of=blob.bin bs=1k count=1", "fs_dd_of"),
    ('find . -name "other.txt" -delete', "fs_find_delete"),
])
def test_s1_the_prefilter_submits_what_the_classifier_calls_destructive(
        tmp_path, command, rule):
    """S1 - cli.py:557. The bash pre-filter is a `case` over a handful of
    substrings; the classifier is a rule table. Where they disagree the
    pre-filter wins, silently, because the guard is never spawned at all.

    Each command below is classified destructive by classify.py and never
    reaches the guard through the bash door. Verified through the LIVE DEBUG
    trap, not a replayed `case`: bash normalises $BASH_COMMAND (`cat a >b`
    becomes `cat a > b`, which the `*> *` pattern does catch), so only the
    live trap is authoritative about this frontier.

    THERE IS A FLOOR, AND IT IS OPT-IN. syscall_guard.py traps rename(2) and
    unlinkat(2), which is precisely what `mv` and `find -delete` do, so those
    two ARE caught - but only under `demo_cli run <cmd>` (cli.py:1110), an
    explicit per-command wrapper. Nothing an agent runs through the Bash tool,
    and nothing typed into an ordinary shell, goes through it. This test is
    about the door that is always open, not the one you have to ask for."""
    assert classify_pipeline(command).needs_recovery, \
        f"precondition: the classifier should call this {rule}"
    (tmp_path / "keep.txt").write_text("k")
    (tmp_path / "other.txt").write_text("o")
    _r, seen = _run_guarded(tmp_path, RECORDS, command)
    assert any("guard-shell" in c for c in seen), (
        f"{command!r} never reached the guard; the pre-filter dropped a "
        f"command the classifier calls destructive ({rule})")


@requires_bash
@pytest.mark.parametrize("command", [
    "git status", "git log --oneline -1", "git diff", "git branch",
])
def test_s3_reading_git_commands_do_not_spawn_the_guard(tmp_path, command):
    """S3 - cli.py:557 matches `*git *`, so EVERY git command pays a Python
    start-up. Measured on this machine: ~200ms per git command against ~4ms
    for the command itself, a ~50x tax on the most frequent verb in the
    repository. None of these four can destroy anything."""
    _r, seen = _run_guarded(tmp_path, RECORDS, command)
    assert not any("guard-shell" in c for c in seen), (
        f"{command!r} spawned the guard; nothing it can do needs gating")


@requires_bash
def test_s2_the_guard_call_is_bounded(tmp_path):
    """S2 - receipts.py:77 gives the receipt lock a 10s timeout and cli.py:558
    calls the guard with no bound at all, so one stuck lock costs 10s on EVERY
    command that matches the pre-filter. Measured: 192ms free, 10253ms held.

    It does fail open and say so, which is the right shape. The cost is the
    defect."""
    assert "timeout" in _SHELL_GUARD_SNIPPET, (
        "the snippet spawns demo_cli with no time bound; a stuck receipt lock "
        "stalls every matching command for the full DEMO_CLI_LOCK_TIMEOUT")


@requires_bash
def test_s4_a_broken_guard_leaves_a_record(tmp_path):
    """S4 - cli.py:562. When demo_cli cannot run, the snippet prints to stderr
    and returns 0. Correct: a broken guard must not lock the user out. But
    nothing is written anywhere, so the receipts - the audit trail this tool
    exists to produce - contain no trace that a destructive command ran
    unguarded. Verified: 0 receipts and no .demo_cli directory at all, against
    1 receipt for the same command with a working guard.

    This test does not prescribe WHERE the record goes; only that one exists."""
    (tmp_path / "victim.txt").write_text("v")
    r, _seen = _run_guarded(tmp_path, BROKEN, "rm -f victim.txt")
    assert "not working" in r.stderr, "precondition: the escape hatch fired"

    records = [p for p in tmp_path.rglob("*")
               if p.is_file() and p.suffix in (".jsonl", ".log")
               and "victim" in p.read_text(errors="ignore")]
    assert records, (
        "a destructive command ran unguarded and nothing recorded it; "
        "the receipts are silent about the one case they most need to show")


@requires_bash
def test_s5_installing_demo_cli_protects_an_already_open_shell(tmp_path):
    """S5 - cli.py:529. `command -v demo_cli` is evaluated once, when the
    snippet is sourced. A shell open at install time never installs the trap
    and never will, and nothing tells the user their session is unguarded.
    Verified: trap -p DEBUG is empty at load and still empty after demo_cli
    becomes resolvable."""
    (tmp_path / "victim.txt").write_text("v")
    binn = tmp_path / "bin"
    binn.mkdir(exist_ok=True)
    r, seen = _run_guarded(
        tmp_path, RECORDS,
        f'command -v demo_cli >/dev/null 2>&1 && echo PRELOADED; '
        f'export PATH="{binn}:$PATH"; '
        f'command -v demo_cli >/dev/null 2>&1 && echo NOW_AVAILABLE; '
        f'rm -f victim.txt',
        preload=False)
    assert "PRELOADED" not in r.stdout, \
        "precondition: demo_cli must NOT be resolvable when the snippet loads"
    assert "NOW_AVAILABLE" in r.stdout, \
        "precondition: demo_cli must be resolvable by the time rm runs"
    assert any("guard-shell" in c for c in seen), (
        "demo_cli became available and the running shell stayed unguarded")


@requires_bash
def test_kill_the_disable_switch_works_in_an_already_open_shell(tmp_path):
    """KILL - cli.py:529 checks DEMO_CLI_DISABLE once, at load; the trap body
    at cli.py:551 never looks at it again. Setting it in a running shell does
    nothing, and the stderr the guard itself prints - "silence it with export
    DEMO_CLI_DISABLE=1" - is advice that does not work where it is given.

    test_shell_guard.py::test_the_kill_switch_turns_the_guard_off passes the
    variable into a NEW shell, where the top-level `if` sees it and no trap is
    installed. That path works and is not this one."""
    (tmp_path / "victim.txt").write_text("v")
    r, seen = _run_guarded(
        tmp_path, BLOCKS,
        'export DEMO_CLI_DISABLE=1; rm -f victim.txt; echo RAN')
    assert "RAN" in r.stdout, (
        "DEMO_CLI_DISABLE=1 did not release the shell it was set in - which "
        "is the shell the guard tells the user to set it in")
    assert not any("guard-shell" in c for c in seen), \
        "the guard was still spawned after the kill switch was set"


def test_asym_uninstall_does_not_remove_a_hook_that_is_not_ours(tmp_path):
    """ASYM - install compares by == (hooks/claude_code.py:269), uninstall by
    substring (lifecycle.py:161). A third-party entry that merely MENTIONS
    `demo_cli hook` is invisible to install and deleted by teardown. Teardown
    is supposed to remove what setup added; here it removes someone else's
    tooling and says nothing."""
    foreign = {"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [
            {"type": "command", "command": "my-audit-tool --wrap 'demo_cli hook' --log"},
            {"type": "command", "command": "unrelated-linter"},
        ]},
    ]}}
    _strip_hook_entries(foreign, "PreToolUse", "demo_cli hook")
    survivors = [h["command"] for b in foreign.get("hooks", {}).get("PreToolUse", [])
                 for h in b.get("hooks", [])]
    assert any("my-audit-tool" in s for s in survivors), (
        f"teardown deleted a third-party hook it did not install; "
        f"survivors: {survivors}")


def test_egress_does_not_claim_an_unattributable_listener(tmp_path, monkeypatch):
    """EGRESS - guarded.py:102. port_open() answers "is anything listening",
    and doctor.py:312 renders that as a green "egress proxy listening on
    :PORT". A stale mitmdump from another project, or any unrelated service,
    earns this project a tick for a proxy that is not gating its traffic.

    FIXING THIS NEEDS A DESIGN DECISION, not just a patch: demo_cli has to be
    able to tell ITS proxy from a stranger's - a health endpoint, a pidfile
    checked against the listener, or an explicit "cannot attribute" state. The
    assertion is deliberately weak: doctor may say ok, or warn, or say it
    cannot tell, but it must not report an unqualified green for a socket it
    has never identified."""
    from demo_cli import doctor as doctor_mod
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    monkeypatch.chdir(tmp_path)
    cfg = Config(project_root=str(tmp_path))
    port, err = cfg.resolve_egress_port()
    assert not err

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
    except OSError:
        pytest.skip(f"port {port} is not bindable on this machine")
    s.listen(5)
    try:
        rows = doctor_mod._egress_checks(cfg)
        proxy = [r for r in rows if "egress proxy" in str(r)]
        assert proxy, "no egress proxy row at all"
        assert not any(str(r[0]) == "ok" for r in proxy), (
            f"an unattributed socket earned a green egress tick: {proxy}")
    finally:
        s.close()


# ==========================================================================
# Tier 3 - text judged as if it were a command, and cost
# ==========================================================================

def test_quote_a_quoted_command_is_text_not_a_command():
    """QUOTE - classify.py:100. `echo "rm -rf /"` prints eight characters. The
    rm_rf rule searches the raw string, so the quoting that makes it inert is
    exactly the thing the classifier ignores."""
    r = classify_pipeline('echo "rm -rf /"')
    assert not r.is_destructive, \
        f"quoted text classified as {r.matched_rule}"


@pytest.mark.parametrize("command", [
    "grep -rn 'terraform destroy' docs/",
    "terraform destroy --help",
    "gh repo delete --help",
    'echo "we use stripe charge in prod"',
])
def test_o1_reads_and_help_are_not_mutations(command):
    """O1 - classify.py:66 and the surface table at classify.py:212. Rules that
    search anywhere in the string fire on greps, --help, filenames and prose.

    PARTLY FIXED ALREADY, which is why the anchored rules are not listed here:
    container_runtime and package_registry carry the _CMD_PREFIX `^` anchor at
    classify.py:244 and :255, so `cat docker_rm_notes.txt` and a commit message
    mentioning `npm unpublish` no longer fire. That anchor is the shape of the
    fix; these four rules have not had it applied."""
    r = classify_pipeline(command)
    assert not r.is_destructive and r.nonrecoverable_surface is None, (
        f"{command!r} reads or prints; classified {r.matched_rule} "
        f"/ surface {r.nonrecoverable_surface}")


def test_o2_a_heredoc_body_is_data_not_commands():
    """O2 - classify.py:786. The pipeline splitter treats every line as a
    segment, so the BODY of a heredoc - which bash passes to a command as
    stdin, never executes - is classified as commands. Writing documentation
    about `git push --force` is reported as performing it."""
    cmd = "cat <<'EOF' > notes.md\ngit push --force origin main\nEOF"
    r = classify_pipeline(cmd)
    assert r.nonrecoverable_surface is None, (
        f"the heredoc BODY was judged as a command: surface "
        f"{r.nonrecoverable_surface}, segments {r.segments}")


def test_double_fire_an_existing_combined_matcher_is_recognised(tmp_path):
    """DOUBLE-FIRE - hooks/claude_code.py:266. _ours() compares the matcher by
    equality, so a settings.json holding {"matcher": "Bash|PowerShell"} - a
    shape Claude Code accepts, and one earlier demo_cli docs showed - is not
    recognised as ours. The installer appends separate Bash and PowerShell
    blocks and both now match: two hook processes, two snapshots and two
    receipts for one command."""
    p = tmp_path / "settings.json"
    p.write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "Bash|PowerShell",
         "hooks": [{"type": "command", "command": "demo_cli hook", "timeout": 60}]},
    ]}}, indent=2))

    install_into_settings(str(p))
    blocks = json.loads(p.read_text())["hooks"]["PreToolUse"]
    fires = sum(1 for b in blocks
                if "Bash" in [x.strip() for x in b.get("matcher", "").split("|")]
                for h in b.get("hooks", [])
                if h.get("command") == "demo_cli hook")
    assert fires == 1, (
        f"one Bash command would spawn the hook {fires} times; matchers are "
        f"{[b.get('matcher') for b in blocks]}")


# ==========================================================================
# Found 2026-09-26 by reading cli.py rather than its comments. Not in the
# original twenty.
# ==========================================================================

def test_selfexclusion_does_not_skip_a_command_that_merely_names_the_guard(
        tmp_path, monkeypatch):
    """cli.py:592 - cmd_guard_shell self-excludes with a SUBSTRING test:

        if not command or command.startswith("demo_cli") or "guard-shell" in command:
            return 0

    The intent is right (the guard must not recurse into itself), but the test
    is the same unanchored-substring shape as O1, on the under-blocking side.
    Any command whose TEXT happens to contain "guard-shell" - a log file, a
    directory, a branch name - skips the entire shell door: no classification,
    no snapshot, no receipt, no stderr line. Nothing records that a destructive
    command ran unguarded.

    Verified through the live DEBUG trap, enforce mode:
        rm -f logs/ordinary.log     -> snapshot 1940e8b9, receipt written
        rm -f logs/guard-shell.log  -> silence; file deleted; 0 receipts

    NOT reachable by a trailing `# guard-shell` comment: bash strips comments
    out of $BASH_COMMAND before the trap sees it, the same normalisation that
    makes `cat a >b` reach the guard. This is an ordinary filename, not a
    crafted bypass - which is what makes it worth pinning.

    Driven through cmd_guard_shell itself, not the snippet: the self-exclusion
    is in the PYTHON, so a stub demo_cli on a fake PATH cannot see it.
    """
    from demo_cli.cli import cmd_guard_shell

    class _Args:
        def __init__(self, argv):
            self.argv = argv
            self.no_color = True

    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "ordinary.log").write_text("PRECIOUS")
    (logs / "guard-shell.log").write_text("PRECIOUS")
    monkeypatch.chdir(tmp_path)

    from demo_cli import recovery
    from demo_cli.config import load_config

    def _points():
        return len(recovery.load_entries(load_config(str(tmp_path)).recovery_dir))

    cmd_guard_shell(_Args(["rm -f logs/ordinary.log"]))
    control = _points()
    assert control > 0, "precondition: an ordinary delete should be captured"

    cmd_guard_shell(_Args(["rm -f logs/guard-shell.log"]))
    assert _points() > control, (
        "a destructive command was skipped because its own text contained the "
        "guard's subcommand name; nothing classified, snapshotted or recorded it")
