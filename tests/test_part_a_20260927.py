"""Part A (2026-09-27): five fixes that do not wait for the redesign.

  A1   demo_cli's own files - config, workspace (ledger, recovery store),
       hook configs, the shell-guard script - cannot be changed by a command
       or an edit. A1b: an agent cannot run a demo_cli subcommand that
       changes demo_cli's state, or uninstall it.
  A2   no recovery point is stored inside what the command destroys.
  A3   a database target comes from the command that writes it.
  A4   the hook imports only what it needs.
  A5   the trap pre-filter ignores harmless /dev/null redirects.

Every negative assertion has a control beside it, and every control passes
on the source before Part A as well.
"""
import io
import json
import os

import pytest

from demo_cli.config import load_config
from demo_cli.guard import Guard, agent_directory

POSIX, POWERSHELL = "posix", "powershell"
SHELL_GUARD = ".demo_cli_shellguard.sh"


def _write(root, files):
    for rel, text in files.items():
        p = os.path.join(str(root), rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    _write(h, {".claude/settings.json": "{}", SHELL_GUARD: "# guard\n",
               "other.sh": "x", "notes.txt": "x"})
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("USERPROFILE", str(h))
    return h


@pytest.fixture
def proj(tmp_path, home):
    """An enforce-mode project with every kind of control-plane file, and
    ordinary files for the controls. No .git anywhere, so nothing spawns git."""
    root = tmp_path / "proj"
    _write(root, {
        ".demo_cli.toml": 'mode = "enforce"\n',
        ".demo_cli/receipts.jsonl": "",
        ".claude/settings.json": "{}",
        ".codex/hooks.json": "{}",
        ".cursor/hooks.json": "{}",
        "notes.txt": "n", "a.txt": "a", "x.toml": "x", "dir/d.txt": "d",
        "sub/.demo_cli/f.txt": "a user directory that shares the name",
    })
    return root


def _eval(root, command, dialect=POSIX):
    with agent_directory(str(root)):
        return Guard(config=load_config(str(root))).evaluate(command, dialect=dialect)


def _edit(root, path):
    with agent_directory(str(root)):
        return Guard(config=load_config(str(root))).evaluate_file_edit(path)


def _refused(r):
    return (r.decision.decision == "ESCALATE"
            and r.classification.matched_rule == "control_plane")


# ==========================================================================
# A1 - demo_cli's own files
#
# Measured before this change, in enforce mode: every row below was
# REVERSIBLE or ALLOW and ran, and `rm -rf .demo_cli` stored its recovery
# point inside the folder it deleted.
# ==========================================================================

# (changes demo_cli's own files, dialect,
#  the same verb on an ordinary file, its decision before Part A)
CONTROL_PLANE_COMMANDS = [
    ("echo > .demo_cli.toml", POSIX, "echo > notes.txt", "REVERSIBLE"),
    ("echo x >> .demo_cli.toml", POSIX, "echo x >> notes.txt", "ALLOW"),
    ("rm .demo_cli/receipts.jsonl", POSIX, "rm notes.txt", "REVERSIBLE"),
    ("rm -rf .demo_cli", POSIX, "rm -rf dir", "REVERSIBLE"),
    ("rm -rf .demo*", POSIX, "rm -rf not*", "REVERSIBLE"),
    ("mv .demo_cli.toml old.toml", POSIX, "mv notes.txt old.txt", "ALLOW"),
    ("cp x.toml .demo_cli.toml", POSIX, "cp x.toml notes.txt", "REVERSIBLE"),
    ("sed -i s/enforce/shadow/ .demo_cli.toml", POSIX,
     "sed -i s/a/b/ notes.txt", "REVERSIBLE"),
    ("cd .claude && rm settings.json", POSIX, "cd dir && rm d.txt", "REVERSIBLE"),
    # Creation counts: settings.local.json does not exist yet.
    ("echo '{}' > .claude/settings.local.json", POSIX,
     "echo '{}' > new.json", "ALLOW"),
    ("rm -rf .claude", POSIX, "rm -rf dir", "REVERSIBLE"),
    ("truncate -s 0 .demo_cli.toml", POSIX, "truncate -s 0 notes.txt", "REVERSIBLE"),
    ("rm ~/" + SHELL_GUARD, POSIX, "rm ~/other.sh", "ESCALATE"),
    ("echo 'trap - DEBUG' >> ~/" + SHELL_GUARD, POSIX,
     "echo x >> ~/other.sh", "ALLOW"),
    ("Remove-Item -Recurse -Force .demo_cli", POWERSHELL,
     "Remove-Item -Recurse -Force dir", "REVERSIBLE"),
    ("Set-Content .demo_cli.toml x", POWERSHELL, "Set-Content notes.txt x", "ESCALATE"),
]


@pytest.mark.parametrize("command,dialect,control,before", CONTROL_PLANE_COMMANDS)
def test_a1_a_command_that_changes_demo_clis_own_files_escalates(
        proj, command, dialect, control, before):
    r = _eval(proj, control, dialect)
    assert r.decision.decision == before, "control: an ordinary file is judged as before"
    assert r.classification.matched_rule != "control_plane", "control"

    r = _eval(proj, command, dialect)
    assert _refused(r), (r.decision.decision, r.classification.matched_rule)
    assert not r.allowed
    assert r.recovery_entry is None, "nothing is captured into the store being changed"
    assert "demo_cli's own files" in r.decision.reason
    assert r.decision.next_steps == ["Make this change yourself, outside the agent."]


# (demo_cli's own file, an ordinary file, the ordinary edit's decision before)
CONTROL_PLANE_EDITS = [
    (".demo_cli.toml", "notes.txt", "REVERSIBLE"),
    (".demo_cli/receipts.jsonl", "notes.txt", "REVERSIBLE"),
    (".claude/settings.json", "notes.txt", "REVERSIBLE"),
    (".claude/settings.local.json", "new.txt", "ALLOW"),     # created
    (".codex/hooks.json", "notes.txt", "REVERSIBLE"),
    (".cursor/hooks.json", "notes.txt", "REVERSIBLE"),
    ("{home}/.claude/settings.json", "{home}/notes.txt", "ESCALATE"),
]


@pytest.mark.parametrize("path,control,before", CONTROL_PLANE_EDITS)
def test_a1_editing_demo_clis_own_files_escalates(proj, home, path, control, before):
    r = _edit(proj, control.format(home=home))
    assert r.decision.decision == before, "control"
    assert r.classification.matched_rule != "control_plane", "control"

    r = _edit(proj, path.format(home=home))
    assert _refused(r), (r.decision.decision, r.classification.matched_rule)
    assert not r.allowed and r.recovery_entry is None


# (reads demo_cli's own files, an ordinary write judged beside it)
READS = [
    "cat .demo_cli.toml",
    "grep x .demo_cli/receipts.jsonl",
    "cp .demo_cli.toml backup.toml",
    "ls .demo_cli",
    "cat .claude/settings.json > copy.json",
    'echo "rm -rf .demo_cli"',
]


@pytest.mark.parametrize("command", READS)
def test_a1_reading_demo_clis_own_files_stays_allowed(proj, command):
    r = _eval(proj, "echo > notes.txt")
    assert r.decision.decision == "REVERSIBLE", "control: the guard is live, in enforce"

    r = _eval(proj, command)
    assert r.decision.decision == "ALLOW"
    assert r.classification.matched_rule != "control_plane"


def test_a1_the_refusal_is_recorded_as_control_plane(proj):
    _eval(proj, "rm -rf .demo_cli")
    with open(proj / ".demo_cli" / "receipts.jsonl", encoding="utf-8") as f:
        last = json.loads(f.read().splitlines()[-1])
    assert last["action_raw"] == "rm -rf .demo_cli", "control: this command's receipt"
    assert last["decision"] == "ESCALATE"
    assert last["matched_rule"] == "control_plane"
    assert last["recovery_point"] is None


def test_a1_shadow_mode_records_the_refusal_and_does_not_block(tmp_path, home):
    root = tmp_path / "shadowproj"
    _write(root, {".demo_cli.toml": 'mode = "shadow"\n', ".demo_cli/receipts.jsonl": ""})
    r = _eval(root, "git push --force origin main")
    assert (r.decision.decision, r.allowed) == ("ESCALATE", True), \
        "control: shadow never blocks, even an escalation"

    r = _eval(root, "rm -rf .demo_cli")
    assert _refused(r)
    assert r.allowed, "shadow records only"


def test_a1_a_user_directory_that_shares_the_name_is_not_demo_clis(proj):
    """Path-based, as the workspace skip has been since R4: sub/.demo_cli is
    the user's, and is judged like any directory."""
    r = _eval(proj, "rm -rf .demo_cli")
    r2 = _eval(proj, "rm -rf sub/.demo_cli")
    assert r2.decision.decision == "REVERSIBLE", "control: judged as before"
    assert r2.classification.matched_rule != "control_plane"
    assert r2.target is not None and r2.target.ref.endswith(os.path.join("sub", ".demo_cli"))
    assert _refused(r)


def test_a1_a_configured_workspace_is_protected_where_it_is(tmp_path, home):
    root = tmp_path / "wsproj"
    _write(root, {".demo_cli.toml": 'mode = "enforce"\n[workspace]\ndir = "state"\n',
                  "state/receipts.jsonl": "", ".demo_cli/f.txt": "now just a directory"})
    r = _eval(root, "rm -rf .demo_cli")
    assert r.decision.decision == "REVERSIBLE", "control: an ordinary directory now"
    assert r.classification.matched_rule != "control_plane"

    r = _eval(root, "rm -rf state")
    assert _refused(r)


# ==========================================================================
# A1b - an agent running demo_cli against itself
# ==========================================================================

def _claude(root, command, tool="Bash"):
    from demo_cli.hooks.claude_code import run_pretooluse
    out = io.StringIO()
    run_pretooluse(io.StringIO(json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": tool, "cwd": str(root),
        "tool_input": {"command": command}})), out)
    raw = out.getvalue()
    # B1 (msg 041): proceed is silent; the notice moved to additionalContext/systemMessage.
    if not raw.strip():
        return "(proceed)"
    return json.loads(raw)["hookSpecificOutput"]["permissionDecision"]


# (changes demo_cli's state, a harmless neighbour allowed before and after)
AGENT_SELF_COMMANDS = [
    ("demo_cli teardown", "demo_cli status"),
    ("demo_cli init", "demo_cli undo abc123"),
    ("demo_cli target add prod", "demo_cli target list"),
    ("demo_cli egress --trust-ca", "demo_cli egress --port 8080"),
    ("demo_cli egress --untrust", "demo_cli doctor"),
    ("python3 -m demo_cli prune --keep 0", "python3 -m demo_cli log"),
    ("/home/u/.local/bin/demo_cli unprotect", "/home/u/.local/bin/demo_cli status"),
    ("cd dir && demo_cli install-hook", "cd dir && demo_cli doctor"),
    ("demo_cli verify --anchor", "demo_cli verify"),
    ("sudo demo_cli teardown", "echo demo_cli teardown"),
    ("DC=demo_cli; $DC teardown", "DC=demo_cli; $DC report"),
    ("pipx uninstall demo-cli", "pipx uninstall httpie"),
    ("pip uninstall -y demo_cli", "pip uninstall -y requests"),
    ("python3 -m pip uninstall demo-cli", "python3 -m pip uninstall requests"),
]


@pytest.mark.parametrize("command,neighbour", AGENT_SELF_COMMANDS)
def test_a1b_an_agent_changing_demo_clis_state_is_denied(proj, command, neighbour, monkeypatch):
    # B1 (msg 041): proceed is silent; the notice moved to additionalContext/systemMessage.
    # M2.3a: some neighbours run code (pip, python3 -m ...) and would be rewritten
    # where a runtime net exists; with none, they proceed on every machine.
    from demo_cli import mountstate, syscall_guard
    from demo_cli.mountstate import MountStatus
    monkeypatch.setattr(syscall_guard, "available", lambda: False)
    monkeypatch.setattr(mountstate, "status", lambda cfg: MountStatus(recorded=False, running=False))
    assert _claude(proj, neighbour) == "(proceed)", "control"
    assert _claude(proj, command) == "deny"


def test_a1b_the_powershell_tool_is_an_agent_door_too(proj):
    # B1 (msg 041): proceed is silent; the notice moved to additionalContext/systemMessage.
    assert _claude(proj, "demo_cli status", tool="PowerShell") == "(proceed)", "control"
    assert _claude(proj, "demo_cli teardown", tool="PowerShell") == "deny"


def test_a1b_codex_and_cursor_deny_it_too(proj):
    from demo_cli.hooks.codex import run_pretooluse as codex
    from demo_cli.hooks.cursor import run_before_shell as cursor

    def run_codex(command):
        out = io.StringIO()
        codex(io.StringIO(json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                      "cwd": str(proj), "tool_input": {"command": command},
                                      "session_id": "s"})), out)
        return out.getvalue()

    def run_cursor(command):
        out = io.StringIO()
        cursor(io.StringIO(json.dumps({"command": command, "cwd": str(proj)})), out)
        return json.loads(out.getvalue())["permission"]

    assert run_codex("demo_cli status") == "", "control: Codex proceeds on silence"
    said = run_codex("demo_cli teardown")
    assert said, "Codex was told nothing, so it proceeds"
    assert json.loads(said)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert run_cursor("demo_cli status") == "allow", "control"
    assert run_cursor("demo_cli teardown") == "deny"


def test_a1b_only_the_agent_doors_judge_demo_cli_subcommands(proj):
    """`demo_cli check` and the `!` trap are the human's doors."""
    r = _eval(proj, "demo_cli teardown")
    assert r.decision.decision == "ALLOW"
    assert r.classification.matched_rule != "control_plane"


def test_a1b_guard_shell_still_skips_demo_clis_own_invocations(proj):
    from demo_cli.cli import main
    ledger = proj / ".demo_cli" / "receipts.jsonl"
    with agent_directory(str(proj)):
        assert main(["guard-shell", "rm", "-rf", "dir"]) == 0
        written = ledger.read_text(encoding="utf-8").count("\n")
        assert written >= 1, "control: guard-shell evaluated and recorded that one"
        assert main(["guard-shell", "demo_cli", "teardown"]) == 0
    assert ledger.read_text(encoding="utf-8").count("\n") == written, \
        "skipped without evaluating, as before"


# ==========================================================================
# A2 - no recovery point inside what is destroyed
#
# recovery.snapshot refused a target INSIDE the recovery store and never the
# other way round, so a directory holding the store was "captured" into that
# store - and destroyed with it by the very command it was captured for.
# ==========================================================================

def test_a2_a_directory_holding_the_store_gets_no_recovery_point(tmp_path):
    from demo_cli import recovery
    root = tmp_path / "p"
    _write(root, {"src/a.py": "code", ".demo_cli/receipts.jsonl": ""})
    rec = str(root / ".demo_cli" / "recovery")

    sibling = recovery.snapshot(recovery.Target("dir", str(root / "src"), "src"), rec)
    assert sibling is not None, "control: a sibling directory is still captured"

    notes = {}
    entry = recovery.snapshot(recovery.Target("dir", str(root), "p"), rec, notes=notes)
    assert entry is None
    assert "recovery store" in notes.get("refused", "")


def test_a2_a_named_target_holding_the_store_escalates_and_says_why(tmp_path, home):
    """`demo_cli check "rm -rf build" --target .` - the explicit --target is
    the door A1 does not cover: the command names build/, the capture names
    the root that holds the store."""
    root = tmp_path / "p"
    _write(root, {".demo_cli.toml": 'mode = "enforce"\n', "src/a.py": "code",
                  "build/o.o": "o"})
    with agent_directory(str(root)):
        g = Guard(config=load_config(str(root)))
        r = g.evaluate("rm -rf build", target_path=str(root / "src"))
        assert r.decision.decision == "REVERSIBLE", "control: a named sibling is captured"
        r = g.evaluate("rm -rf build", target_path=str(root))
    assert r.decision.decision == "ESCALATE"
    assert r.recovery_entry is None
    assert "recovery store" in r.decision.reason


def test_a2_the_checkpoint_still_works_and_states_its_residual(tmp_path, home):
    root = tmp_path / "p"
    _write(root, {".demo_cli.toml": 'mode = "enforce"\n[checkpoint]\nenabled = true\n',
                  "src/a.py": "code"})
    r = _eval(root, "rm -rf $(cat list.txt)")
    assert r.decision.decision == "REVERSIBLE", "control: the checkpoint is taken"
    assert r.recovery_entry is not None, "control"
    assert "deletes it too" in r.decision.reason, \
        "the checkpoint lives inside the tree it protects, and says so"


# ==========================================================================
# A3 - the database target comes from the statement that writes it
# ==========================================================================

@pytest.fixture
def dbproj(tmp_path, home):
    import sqlite3
    root = tmp_path / "dbp"
    _write(root, {".demo_cli.toml": 'mode = "enforce"\n'})
    for rel in ("app.db", "data/users.db", "other.db"):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(str(path))
        con.execute("create table t(id)")
        con.execute("create table users(id)")
        con.execute("insert into t values (1)")
        con.execute("insert into users values (1)")
        con.commit()
        con.close()
    return root


def _target(r, root):
    return os.path.relpath(r.target.ref, str(root)) if r.target else None


def _captured_targets(root):
    from demo_cli import recovery
    return {os.path.relpath(e["target"], str(root))
            for e in recovery.load_entries(str(root / ".demo_cli" / "recovery"))}


CONTROL_SQL = 'sqlite3 app.db "DELETE FROM t WHERE id=1"'


def test_a3_the_database_written_is_the_one_captured(dbproj):
    r = _eval(dbproj, CONTROL_SQL)
    assert (r.decision.decision, _target(r, dbproj)) == ("DRY_RUN", "app.db"), "control"

    root2 = dbproj.parent / "dbp2"
    import shutil
    shutil.copytree(str(dbproj), str(root2), ignore=shutil.ignore_patterns(".demo_cli"))
    r = _eval(root2, 'echo app.db >/dev/null; sqlite3 data/users.db '
                     '"DELETE FROM users WHERE id=1"')
    assert _target(r, root2) == os.path.join("data", "users.db")
    assert r.decision.decision == "DRY_RUN"
    assert _captured_targets(root2) == {os.path.join("data", "users.db")}, \
        "app.db was only mentioned; it must not be what is captured"


def test_a3_two_databases_in_the_statement_that_writes_escalate(dbproj):
    r = _eval(dbproj, CONTROL_SQL)
    assert r.decision.decision == "DRY_RUN", "control: one database is captured"

    cmd = 'sqlite3 app.db "ATTACH \'other.db\' AS o; DELETE FROM o.t"'
    app_data = (dbproj / "app.db").read_bytes()
    other_data = (dbproj / "other.db").read_bytes()
    r = _eval(dbproj, cmd)
    if ENGINE_PATH:
        assert r.decision.decision == "REVERSIBLE"
        assert_restores(r.recovery_entry, dbproj, {
            "app.db": app_data,
            "other.db": other_data,
        })
    else:
        assert (r.decision.decision, _target(r, dbproj)) == ("ESCALATE", None)


def test_a3_an_echoed_url_does_not_beat_the_database_written(dbproj):
    r = _eval(dbproj, 'psql postgres://u:p@remote.example.com/x -c "DELETE FROM t"')
    assert r.decision.decision == "ESCALATE", "control: a remote database written escalates"
    assert r.classification.nonrecoverable_surface in ("remote_database", "managed_database"), "control"

    r = _eval(dbproj, "echo postgres://u:p@remote.example.com/x; " + CONTROL_SQL)
    assert (r.decision.decision, _target(r, dbproj)) == ("DRY_RUN", "app.db")


# The statement, not the unit: these keep their database (and passed before).
SAME_DATABASE = [
    ('echo "DELETE FROM t WHERE id=1" | sqlite3 app.db', "app.db", "DRY_RUN"),
    ("sqlite3 app.db <<EOF\nDELETE FROM t WHERE id=1;\nEOF", "app.db", "REVERSIBLE"),
    ('DB=app.db; sqlite3 $DB "DELETE FROM t WHERE id=1"', "app.db", "DRY_RUN"),
    ("cp app.db app.bak && " + CONTROL_SQL, "app.db", "DRY_RUN"),
    ('sqlite3 data/users.db "DELETE FROM users WHERE id=1"  # app.db',
     os.path.join("data", "users.db"), "DRY_RUN"),
]


@pytest.mark.parametrize("command,db,expected_decision", SAME_DATABASE)
def test_a3_the_statement_keeps_its_database(dbproj, command, db, expected_decision):
    r = _eval(dbproj, command)
    assert _target(r, dbproj) == db
    assert r.decision.decision == expected_decision


# ==========================================================================
# A4 - the hook imports only what it needs
# ==========================================================================

def _fresh_python(script, tmp_path, extra_path=None):
    """Run `script` in a new interpreter against THIS source tree."""
    import subprocess
    import sys
    import demo_cli
    src = os.path.dirname(os.path.dirname(os.path.abspath(demo_cli.__file__)))
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(([extra_path] if extra_path else []) + [src])
    r = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                       cwd=str(tmp_path), env=env, timeout=120)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


HEAVY = ["demo_cli.lifecycle", "demo_cli.doctor", "demo_cli.egress", "demo_cli.fsmount",
         "demo_cli.protect", "demo_cli.guarded", "demo_cli.schedule", "mitmproxy"]


def test_a4_importing_the_cli_loads_none_of_the_commands_a_hook_never_runs(tmp_path):
    out = _fresh_python(
        "import json, sys\n"
        "import demo_cli.cli as cli\n"
        f"loaded = [m for m in {HEAVY!r} if m in sys.modules]\n"
        "from demo_cli import doctor\n"
        "same = cli.cmd_doctor is doctor.cmd_doctor\n"
        "print(json.dumps({'loaded': loaded, 'same': same,\n"
        "                  'doctor_now': 'demo_cli.doctor' in sys.modules}))\n",
        tmp_path)
    assert out["same"] and out["doctor_now"], \
        "control: a re-exported name still resolves to the real object"
    assert out["loaded"] == []


def test_a4_a_monkeypatched_re_export_still_reaches_the_cli_code(tmp_path, monkeypatch):
    from demo_cli import cli
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_CONFIG_TEMPLATE", 'mode = "shadow"  # patched\n')
    assert cli.main(["init"]) == 0
    assert "# patched" in (tmp_path / ".demo_cli.toml").read_text(encoding="utf-8")


def test_a4_importing_egress_builds_no_mitmproxy_addon(tmp_path):
    """A stand-in `mitmproxy` package, so this runs where the real one is
    not installed (the Windows venv) and cannot be satisfied by it."""
    fake = tmp_path / "fake"
    _write(fake, {"mitmproxy/__init__.py": "",
                  "mitmproxy/http.py": "class Response:\n"
                                       "    @staticmethod\n"
                                       "    def make(*a, **k):\n"
                                       "        return None\n"})
    out = _fresh_python(
        "import json, sys\n"
        "import demo_cli.egress as e\n"
        "built = hasattr(e, 'addons') and bool(e.addons)\n"
        "import demo_cli.egress_addon as entry\n"
        "print(json.dumps({'built_on_import': built, 'entry': len(entry.addons)}))\n",
        tmp_path, extra_path=str(fake))
    assert out["entry"] == 1, "control: the mitmdump entry point still builds the addon"
    assert not out["built_on_import"]


# ==========================================================================
# A5 - the trap pre-filter ignores harmless /dev/null redirects
#
# bash hands the trap `2>/dev/null` as `2> /dev/null`, which the `*\>\ *` arm
# matched - so the agent Bash tool's own wrapper line started guard-shell
# (~160 ms) twice per call. Real bash, the real snippet, a recording stub.
# ==========================================================================

def _trap():
    from test_audit_20260926 import BASH, RECORDS, _run_guarded
    if BASH is None:
        pytest.skip("no bash for this platform")
    return RECORDS, _run_guarded


WRAPPER = ("source ./snap.sh 2>/dev/null || true && "
           "shopt -u extglob 2>/dev/null || true && eval '{}'")


def test_a5_the_agent_tool_wrapper_line_no_longer_starts_the_guard(tmp_path):
    records, run = _trap()
    (tmp_path / "snap.sh").write_text("")
    (tmp_path / "control.txt").write_text("c")
    _r, seen = run(tmp_path, records, WRAPPER.format("rm -f control.txt"))
    assert "guard-shell rm -f control.txt" in seen, "control: the real command is sent"
    assert seen == ["guard-shell rm -f control.txt"], "the wrapper's own lines are not"

    _r, seen = run(tmp_path, records, WRAPPER.format("echo hi"))
    assert seen == []


DEVNULL_ONLY = ["true 2>/dev/null", "ls >/dev/null 2>&1", "true &>/dev/null",
                "true >>/dev/null", "echo x 2>&1 >/dev/null"]


@pytest.mark.parametrize("command", DEVNULL_ONLY)
def test_a5_a_devnull_redirect_alone_does_not_start_the_guard(tmp_path, command):
    records, run = _trap()
    (tmp_path / "control.txt").write_text("c")
    _r, seen = run(tmp_path, records, f"rm -f control.txt; {command}")
    assert "guard-shell rm -f control.txt" in seen, "control: the stub is reached"
    assert len(seen) == 1, seen


# A real target still goes to the guard, and as it was written (passed before too).
STILL_SENT = [
    ("echo x > f.txt", "echo x > f.txt"),
    ("echo x > f.txt 2>/dev/null", "echo x > f.txt 2> /dev/null"),
    ("true 2> /dev/nullx", "true 2> /dev/nullx"),
    ("true xargs rm", "true xargs rm"),
]


@pytest.mark.parametrize("command,sent", STILL_SENT)
def test_a5_a_real_redirect_still_reaches_the_guard_as_written(tmp_path, command, sent):
    records, run = _trap()
    _r, seen = run(tmp_path, records, command)
    assert seen == [f"guard-shell {sent}"]
