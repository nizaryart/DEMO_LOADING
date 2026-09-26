"""Audit 2026-09-26: defects confirmed live at f694dba (v1.7.0).

Each test states the behaviour demo_cli claims to have. Red means the defect
is still there. The suite was green at 1856 passing with all of them reachable,
so nothing in it described these behaviours.

Deliberate overlaps with existing tests:
  * test_symlink_snapshot.py pins the copytree (directory) branch; R3 is the
    copy2 (file) branch, which that file never reaches.
  * test_ignored_dir_capture.py asserts .demo_cli is never un-ignored. R4 must
    therefore be fixed by PATH, not by name - guarded by the companion test.
  * test_shell_guard.py's kill-switch test uses a NEW shell; KILL here is an
    already-open one.
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

def _bash_for_this_platform():
    """Git Bash, never WSL's C:\\Windows\\system32\\bash.EXE.

    WSL bash runs in another filesystem namespace, so tmp_path, BASH_ENV and
    the stub are invisible to it: `any(...)` tests fail and `not any(...)`
    tests pass vacuously. Same detection as test_shell_guard.py.
    """
    if os.name != "nt":
        return shutil.which("bash")
    for candidate in (r"C:\Program Files\Git\bin\bash.exe",
                      r"C:\Program Files (x86)\Git\bin\bash.exe"):
        if os.path.exists(candidate):
            return candidate
    git = shutil.which("git")
    if git:
        cand = os.path.join(os.path.dirname(os.path.dirname(git)), "bin", "bash.exe")
        if os.path.exists(cand):
            return cand
    found = shutil.which("bash")
    if found and "system32" not in found.lower():
        return found
    return None                          # WSL only: not a Windows bash


BASH = _bash_for_this_platform()
requires_bash = pytest.mark.skipif(
    BASH is None, reason="no Windows-native bash (WSL's bash is not Windows)")


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
    """R2 - guard.py. evaluate_file_edit had no project-root bound, so it
    snapshotted and blessed any path on the machine while the shell door
    escalated on the same one.
    """
    outside = tmp_path.parent / "outside_victim.txt"
    outside.write_text("precious")
    g = Guard(Config(project_root=str(proj)), mode="enforce")

    r = g.evaluate_file_edit(str(outside), tool_name="Write")
    assert r.decision.decision != "REVERSIBLE", (
        "a Write outside the project root was called reversible; "
        "the shell door escalates on the same path")


def test_r2_the_project_root_itself_is_not_a_file_edit_target(proj):
    """R2, second shape: evaluate() refuses the project root as a capture
    surface; this door did not.
    """
    g = Guard(Config(project_root=str(proj)), mode="enforce")
    r = g.evaluate_file_edit(str(proj), tool_name="Write")
    assert r.decision.decision != "REVERSIBLE", \
        "the project root itself was accepted as a reversible file edit"


def test_r2_a_home_dotfile_is_not_snapshotted_into_the_project(proj):
    """R2's other half: the file was COPIED into the project's recovery dir.
    Pointed at /etc/hosts or an ssh config, a wrong label is also a leak.
    """
    g = Guard(Config(project_root=str(proj)), mode="enforce")
    victim = os.path.join(os.path.expanduser("~"), ".bashrc")
    if not os.path.isfile(victim):
        pytest.skip("no ~/.bashrc on this machine")
    r = g.evaluate_file_edit(victim, tool_name="Write")
    assert not r.recovery_entry, \
        "a file from $HOME was copied into the project's recovery store"


@requires_symlinks
def test_r3_a_snapshotted_symlink_is_still_a_symlink_after_undo(proj):
    """R3 - recovery.py:338. copy2(ref, bak) has no follow_symlinks=False, so
    the snapshot holds the target's bytes and undo writes them back as a plain
    file. test_symlink_snapshot.py fixed this for copytree, not for copy2.
    """
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
    """R4 - recovery.py:349 + targets.py:48. IGNORED_DIRS matches by NAME, so
    any directory called .demo_cli is dropped from a capture still reported
    REVERSIBLE. Fix by path identity, not by un-ignoring the name - see the
    companion test.
    """
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
    """What R4's fix must not cost: copying the recovery store into itself.
    Passes today and must keep passing.
    """
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
    """cp-f - classify.py has no cp rule, so `cp -f a b` is "non-mutating" and
    b is overwritten with no recovery point.

    CONSTRAINT: adding cp to _DESTRUCTIVE_RULES makes it an acting segment,
    and the multiplicity counter then escalates `rm x && cp a b`, which
    snapshots correctly today. Pinned by test_powershell_aliases.py::
    test_posix_copy_does_not_count_as_a_destructive_step. A fix must give
    `cp -f` a resolvable target without a vote in destructive_segments.
    """
    (proj / "a.txt").write_text("SOURCE")
    (proj / "b.txt").write_text("ORIGINAL - must be recoverable")
    g = Guard(Config(project_root=str(proj)), mode="enforce")
    r = g.evaluate("cp -f a.txt b.txt")
    assert r.recovery_entry, (
        "cp -f overwrote an existing file with no snapshot "
        f"(decision was {r.decision.decision}: {r.decision.reason})")


def test_diff_shows_an_ignored_directory_that_the_capture_holds(proj):
    """DIFF - diff.py:106. The capture lift works and .git IS copied, but
    _manifest() filters IGNORED_DIRS from both sides, so `demo_cli diff` shows
    the capture as if it had none - to the person deciding whether to undo.
    """
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
    """LOG-0B - recovery.py:544. entry_size() returns 0 both for "zero bytes"
    and "cannot stat it", and log renders both as 0B under an undo footer.
    Asks only that the two be distinguishable, not how to render it.
    """
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
    calls = binn / "calls.log"                     # beside the stub; see _LOG
    # Truncate per run: two _run_guarded calls share one tmp_path, so a control
    # run's entries would otherwise still be in `seen` for the run after it.
    if calls.exists():
        calls.unlink()
    stub = binn / "demo_cli"
    with open(stub, "w", newline="\n") as fh:      # CRLF makes the shebang "/bin/sh\r"
        fh.write(stub_body)
    stub.chmod(0o755)

    script = tmp_path / "guard.sh"
    with open(script, "w", newline="\n") as fh:
        fh.write(_SHELL_GUARD_SNIPPET)

    env = dict(os.environ)
    env.pop("DEMO_CLI_DISABLE", None)
    # preload=False must mean NO demo_cli resolvable at snippet-load time. The
    # ambient PATH carries a real pipx install, which silently turned the S5
    # test green by satisfying the very `command -v` it is meant to catch.
    base = env["PATH"] if preload else os.pathsep.join(["/usr/bin", "/bin"])
    env["PATH"] = f"{binn}{os.pathsep}{base}" if preload else base
    env["BASH_ENV"] = str(script)
    # Point the broken-guard breadcrumb inside tmp_path. Without this the
    # snippet's default is $HOME/.demo_cli-shell-guard.log and the suite would
    # write to the developer's real home directory.
    env["DEMO_CLI_FALLBACK_LOG"] = str(tmp_path / "shell-guard.log")
    env.update(env_extra or {})
    r = subprocess.run([BASH, "-c", command], capture_output=True, text=True,
                       env=env, timeout=60, cwd=str(tmp_path))
    seen = calls.read_text().splitlines() if calls.exists() else []
    return r, seen


# $0, NOT A PATH WE SUBSTITUTE IN. The previous version baked the calls-log
# path into the script text unquoted:
#
#     echo "$@" >> C:\Users\pc\AppData\Local\Temp\...\calls.log
#
# On Windows bash reads those backslashes as escapes, the redirect lands
# somewhere else, and `seen` comes back EMPTY for every test - which fails the
# `any(...)` assertions (S1, S5) and silently PASSES the `not any(...)` ones
# (S3, KILL). The second is the dangerous half: four tests went green on
# Windows while proving nothing, 2026-09-26. Second time this harness has
# produced a vacuous pass; deriving the path from $0 removes the class.
_LOG = 'CALLS="$(dirname "$0")/calls.log"\n'
RECORDS = ('#!/bin/sh\n'
           'if [ "$1" = "--version" ]; then echo 1.7.0; exit 0; fi\n'
           + _LOG +
           'echo "$@" >> "$CALLS"\n'
           'exit 0\n')
BROKEN = '#!/bin/sh\necho "SyntaxError: broken" >&2\nexit 1\n'
BLOCKS = ('#!/bin/sh\n'
          'if [ "$1" = "--version" ]; then echo 1.7.0; exit 0; fi\n'
          + _LOG +
          'echo "$@" >> "$CALLS"\n'
          'exit 1\n')


@requires_bash
@pytest.mark.parametrize("command,rule", [
    ("mv keep.txt moved.txt", "mv_overwrite"),
    ("dd if=/dev/zero of=blob.bin bs=1k count=1", "fs_dd_of"),
    ('find . -name "other.txt" -delete', "fs_find_delete"),
])
def test_s1_the_prefilter_submits_what_the_classifier_calls_destructive(
        tmp_path, command, rule):
    """S1 - the bash pre-filter is narrower than the classifier, and what it
    drops no layer on this path ever sees.

    Driven through the live DEBUG trap: bash normalises $BASH_COMMAND, so a
    replayed `case` is not authoritative (`cat a >b` becomes `cat a > b`,
    which the `*> *` pattern does catch).

    syscall_guard traps rename(2) and unlinkat(2), so mv and find -delete have
    a floor - but only under `demo_cli run <cmd>`, never the agent's Bash tool.
    """
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
    """S3 - `*git *` matches every git command, so a read pays a Python
    start-up: ~200ms against ~4ms for the command itself.
    """
    # A CONTROL IN THE SAME SHELL. This assertion is a NEGATIVE, so it passes
    # for free whenever the harness is broken and nothing was recorded - which
    # is exactly what happened on Windows on 2026-09-26, where four of these
    # went green while the stub could not write its log at all. The `rm` proves
    # the trap fired and the stub was reached before the negative means
    # anything.
    (tmp_path / "control.txt").write_text("c")
    _r, seen = _run_guarded(tmp_path, RECORDS, f"rm -f control.txt; {command}")
    assert any("control.txt" in c for c in seen), (
        "harness precondition failed: the stub was never reached, so the "
        "assertion below would pass without proving anything")
    assert not any(command in c for c in seen), (
        f"{command!r} spawned the guard; nothing it can do needs gating")


@requires_bash
def test_s2_the_guard_call_is_bounded(tmp_path):
    """S2 - the ledger lock waits 10s and this call had no bound, so a stuck
    lock cost 10s on every matching command. Measured 192ms free, 10253ms held.
    """
    assert "timeout" in _SHELL_GUARD_SNIPPET, (
        "the snippet spawns demo_cli with no time bound; a stuck receipt lock "
        "stalls every matching command for the full DEMO_CLI_LOCK_TIMEOUT")


@requires_bash
def test_s4_a_broken_guard_leaves_a_record(tmp_path):
    """S4 - when demo_cli cannot run, the hatch allows the command (correct)
    and records nothing (not correct): 0 receipts for a destructive command
    that ran unguarded. Does not prescribe where the record goes.
    """
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
    """S5 - `command -v demo_cli` was evaluated once, at load, so a shell open
    at install time never armed the trap and nothing said so.
    """
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
    """KILL - DEMO_CLI_DISABLE was read once at load, so setting it in a
    running shell did nothing - and that is the shell the guard's own stderr
    tells you to set it in.
    """
    (tmp_path / "victim.txt").write_text("v")
    # Control first: with the switch UNSET the guard must be reached. Without
    # this the `not any(...)` below passes whenever the harness is broken.
    (tmp_path / "control.txt").write_text("c")
    _c, control_seen = _run_guarded(tmp_path, RECORDS, "rm -f control.txt")
    assert any("control.txt" in c for c in control_seen), (
        "harness precondition failed: the stub was never reached")

    r, seen = _run_guarded(
        tmp_path, BLOCKS,
        'export DEMO_CLI_DISABLE=1; rm -f victim.txt; echo RAN')
    assert "RAN" in r.stdout, (
        "DEMO_CLI_DISABLE=1 did not release the shell it was set in - which "
        "is the shell the guard tells the user to set it in")
    assert not any("guard-shell" in c for c in seen), \
        "the guard was still spawned after the kill switch was set"


def test_asym_uninstall_does_not_remove_a_hook_that_is_not_ours(tmp_path):
    """ASYM - install compares by ==, uninstall by substring, so a third-party
    entry that merely mentions `demo_cli hook` is invisible to install and
    deleted by teardown.
    """
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
    """EGRESS - port_open() answers "is anything listening" and doctor renders
    that as a green tick, so a stranger's socket earns this project credit for
    a proxy that is not gating its traffic.

    NEEDS A DESIGN DECISION: demo_cli must be able to tell its proxy from a
    stranger's. The assertion is weak on purpose - ok, warn or "cannot tell"
    are all acceptable; an unqualified green is not.
    """
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
    """QUOTE - `echo "rm -rf /"` prints eight characters, but rm_rf searches
    the raw string, so the quoting that makes it inert is what is ignored.
    """
    r = classify_pipeline('echo "rm -rf /"')
    assert not r.is_destructive, \
        f"quoted text classified as {r.matched_rule}"


def test_quote_a_commit_message_is_not_a_command(proj):
    """QUOTE end to end, where it costs something: in enforce mode
    `git commit -m "rm -rf a.txt"` is ESCALATE / deny.

    recovery.expanded_operands returns [] for the same string (pinned by
    test_affected_preview.py) because targets._RM_RE is ^-anchored - the
    operand layer and the classifier disagree, and only one side is pinned.

    CONSTRAINT: do not fix by anchoring rm_rf. It is unanchored on purpose;
    test_unearned_allows.py says so and
    test_the_docker_exclusion_did_not_touch_real_rm pins what depends on it.
    The fix is quote-awareness.
    """
    g = Guard(Config(project_root=str(proj)), mode="enforce")
    r = g.evaluate('git commit -m "rm -rf a.txt"')
    assert r.permission != "deny", (
        f"a commit message was denied: {r.decision.decision} / "
        f"{r.decision.reason}")


@pytest.mark.parametrize("command", [
    "grep -rn 'terraform destroy' docs/",
    "terraform destroy --help",
    "gh repo delete --help",
    'echo "we use stripe charge in prod"',
])
def test_o1_reads_and_help_are_not_mutations(command):
    """O1 - unanchored rules fire on greps, --help and prose.

    Third instance of a twice-fixed class: SQL verbs (test_sql_verb_is_not_sql
    .py) and container/registry verbs (test_unearned_allows.py) were both swept
    and both shipped a corpus of prose that must be RELEASED. Neither corpus
    covers these four. The idiomatic fix is to extend ORDINARY and sweep the
    remaining unanchored rules, not to add a fourth list.
    """
    r = classify_pipeline(command)
    assert not r.is_destructive and r.nonrecoverable_surface is None, (
        f"{command!r} reads or prints; classified {r.matched_rule} "
        f"/ surface {r.nonrecoverable_surface}")


def test_o2_a_heredoc_body_is_data_not_commands():
    """O2 - split_segments splits on newlines with no concept of a heredoc, so
    the BODY - which bash passes as stdin and never executes - is classified
    as commands.
    """
    cmd = "cat <<'EOF' > notes.md\ngit push --force origin main\nEOF"
    r = classify_pipeline(cmd)
    assert r.nonrecoverable_surface is None, (
        f"the heredoc BODY was judged as a command: surface "
        f"{r.nonrecoverable_surface}, segments {r.segments}")


def test_double_fire_an_existing_combined_matcher_is_recognised(tmp_path):
    """DOUBLE-FIRE - _ours() compared the matcher by equality, so a block
    holding "Bash|PowerShell" was not recognised and the installer appended a
    second block for each: two hook processes per command.
    """
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
    """cmd_guard_shell self-excluded by substring, so any command whose text
    contained "guard-shell" - a log file, a directory, a branch name - skipped
    the whole shell door with no classification, snapshot or receipt.

    Not reachable via a trailing `# guard-shell` comment: bash strips comments
    from $BASH_COMMAND. An ordinary filename is enough, which is the point.
    Driven through cmd_guard_shell itself - the check is in the Python, so a
    stub on a fake PATH cannot see it.
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
