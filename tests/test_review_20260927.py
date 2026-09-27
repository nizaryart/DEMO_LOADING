"""The guard's own mechanisms, held to the tool's rules (review 2026-09-27).

Each of these was found by running it, not by reading it:

  PREVIEW   the SQL preview ran the agent's text: `DELETE FROM t WHERE id=1;
            DROP TABLE users` dropped the table while the guard was only
            EVALUATING the command, in shadow mode too.
  PG-QUOTE  a quoted connection string kept its closing quote, so pg_dump
            failed and the command escalated for the wrong reason.
  TOML      `target add "C:\\prod\\app.db"` wrote an invalid escape; every
            command after it was refused over the config.
  BROKEN    an unreadable config said "every command is blocked" and blocked
            nothing - it fell back to shadow, the default mode.
  REDACT    pipeline_segments stored a connection password verbatim while
            action_raw beside it was masked.
  SELFTEST  doctor's hook self-test passed on any well-formed answer, so
            `echo hi` "was intercepted and snapshotted".
  UNDO-DIR  undoing a directory overwrote work done after the snapshot and
            kept no copy of it.
  ELEV-MSG  setup warned the backing would NOT be locked, then elevated and
            locked it.

Every negative assertion has a control beside it that must pass first.
"""
import inspect
import io
import json
import os
import sqlite3

import pytest

from demo_cli import lifecycle, preview, protect, recovery
from demo_cli.config import Config, append_target_rule, load_config
from demo_cli.guard import Guard, agent_directory
from demo_cli.render import feedback_url_for
from demo_cli.targets import resolve_target


# --------------------------------------------------------------------------
# PREVIEW
# --------------------------------------------------------------------------

SMUGGLED = "DELETE FROM t WHERE id=1; DROP TABLE users"


def test_the_preview_refuses_a_second_statement():
    assert preview._preview_queries("DELETE FROM t WHERE id=1;")[0], "control: trailing ;"
    assert preview._preview_queries("DELETE FROM t WHERE name = 'a;b'")[0], "control: quoted ;"
    assert preview._preview_queries(SMUGGLED) == (None, None)
    assert preview._preview_queries(f'psql postgres://h/db -c "{SMUGGLED}"') == (None, None)


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "app.db"
    con = sqlite3.connect(path)
    con.executescript("CREATE TABLE t(id); INSERT INTO t VALUES (1),(2); CREATE TABLE users(id);")
    con.commit()
    con.close()
    return str(path)


def _tables(path):
    con = sqlite3.connect(path)
    try:
        return sorted(r[0] for r in con.execute("SELECT name FROM sqlite_master"))
    finally:
        con.close()


def test_the_sqlite_preview_counts_and_writes_nothing(db):
    assert preview.preview_sqlite("DELETE FROM t WHERE id=1", db)[0] == 1, "control"
    preview.preview_sqlite(SMUGGLED, db)
    assert _tables(db) == ["t", "users"]


def test_the_sqlite_preview_does_not_create_a_missing_database(tmp_path):
    missing = tmp_path / "nope.db"
    assert preview.preview_sqlite("DELETE FROM t WHERE id=1", str(missing))[0] is None
    assert not missing.exists()


def test_the_postgres_preview_runs_read_only(monkeypatch):
    calls = []

    class Done:
        stdout = "3\n"

    def fake_run(args, **kw):
        calls.append((args, kw.get("env") or {}))
        return Done()

    monkeypatch.setattr(preview.shutil, "which", lambda name: "/usr/bin/psql")
    monkeypatch.setattr(preview.subprocess, "run", fake_run)

    count, _rows, _cols = preview.preview_postgres("DELETE FROM t WHERE id=1", "postgres://h/db")
    assert count == 3 and len(calls) == 2, "control: a single statement is previewed"
    for _args, env in calls:
        assert "default_transaction_read_only=on" in env.get("PGOPTIONS", "")

    calls.clear()
    assert preview.preview_postgres(SMUGGLED, "postgres://h/db")[0] is None
    assert calls == [], "a second statement must never reach psql"


# --------------------------------------------------------------------------
# PG-QUOTE
# --------------------------------------------------------------------------

def test_a_quoted_connection_string_is_read_without_its_quote():
    bare = resolve_target('psql postgresql://u@h/db -c "DELETE FROM t"')
    assert bare.ref == "postgresql://u@h/db", "control"
    for quoted in ('psql "postgresql://u@h/db" -c "DELETE FROM t"',
                   "psql 'postgresql://u@h/db' -c 'DELETE FROM t'"):
        assert resolve_target(quoted).ref == "postgresql://u@h/db", quoted


# --------------------------------------------------------------------------
# TOML
# --------------------------------------------------------------------------

@pytest.mark.parametrize("pattern", ["prod.db", r"C:\prod\app.db", 'a"b', r"\\srv\share"])
def test_target_add_writes_a_config_that_still_parses(tmp_path, pattern):
    append_target_rule(root=str(tmp_path), match=pattern)
    cfg = load_config(str(tmp_path))
    assert cfg.config_error is None, cfg.config_error
    assert [t.match for t in cfg.targets] == [pattern]
    with agent_directory(str(tmp_path)):
        assert Guard(config=cfg).evaluate("ls").decision.decision == "ALLOW"


def test_target_add_refuses_a_control_character(tmp_path):
    with pytest.raises(ValueError):
        append_target_rule(root=str(tmp_path), match="a\nmode = \"shadow\"")
    assert not (tmp_path / ".demo_cli.toml").exists()


# --------------------------------------------------------------------------
# BROKEN
# --------------------------------------------------------------------------

def _hook(cwd, command):
    from demo_cli.hooks.claude_code import run_pretooluse
    out = io.StringIO()
    payload = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(cwd)}
    run_pretooluse(io.StringIO(json.dumps(payload)), out)
    return out.getvalue()


def test_a_broken_config_blocks_at_the_hook(tmp_path):
    ok, broken = tmp_path / "ok", tmp_path / "broken"
    ok.mkdir()
    broken.mkdir()
    (ok / ".demo_cli.toml").write_text('mode = "shadow"\n')
    (broken / ".demo_cli.toml").write_text('mode = "enforce"\nmatch = "C:\\prod"\n')
    assert _hook(ok, "ls") == "", "control: shadow says nothing, so the command runs"
    out = json.loads(_hook(broken, "ls"))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_a_broken_config_blocks_at_the_shell_guard(tmp_path, monkeypatch):
    from demo_cli.cli import main
    (tmp_path / ".demo_cli.toml").write_text('mode = "shadow"\n')
    monkeypatch.chdir(tmp_path)
    assert main(["guard-shell", "ls"]) == 0, "control"
    (tmp_path / ".demo_cli.toml").write_text("mode = = broken\n")
    assert main(["guard-shell", "ls"]) == 1


def test_an_explicit_mode_still_wins_over_a_broken_config(tmp_path):
    (tmp_path / ".demo_cli.toml").write_text("mode = = broken\n")
    cfg = load_config(str(tmp_path))
    assert Guard(config=cfg).mode == "enforce"
    assert Guard(config=cfg, mode="shadow").mode == "shadow"


# --------------------------------------------------------------------------
# REDACT
# --------------------------------------------------------------------------

SECRET = "s3cret"


def test_no_receipt_field_holds_the_password(tmp_path):
    cfg = Config(project_root=str(tmp_path), mode="shadow")
    with agent_directory(str(tmp_path)):
        Guard(config=cfg).evaluate(f"echo postgres://u:{SECRET}@db.example.com/x | cat",
                                   intent=None)
    line = open(cfg.receipts_path).read().splitlines()[-1]
    receipt = json.loads(line)
    assert receipt["pipeline_segments"], "control: the segments are recorded"
    assert "db.example.com" in line, "control: the command is recorded"
    assert SECRET not in line


def test_the_feedback_link_carries_no_password(tmp_path):
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    with agent_directory(str(tmp_path)):
        r = Guard(config=cfg).evaluate(
            f'psql postgres://u:{SECRET}@db.example.com/x -c "DROP TABLE t"')
    url = feedback_url_for(r)
    assert url and "DROP" in url, "control: a link is built and names the command"
    assert SECRET not in url


# --------------------------------------------------------------------------
# SELFTEST
# --------------------------------------------------------------------------

def test_the_hook_self_test_fails_when_nothing_is_captured():
    from demo_cli.doctor import _hook_selftest
    assert _hook_selftest("Bash", "rm -rf canary.txt") is True, "control"
    assert _hook_selftest("Bash", "echo hi") is False


# --------------------------------------------------------------------------
# UNDO-DIR
# --------------------------------------------------------------------------

def _dir_entry(tmp_path):
    tree = tmp_path / "proj" / "tree"
    tree.mkdir(parents=True)
    (tree / "keep.txt").write_text("v1\n")
    rec = str(tmp_path / "rec")
    entry = recovery.snapshot(recovery.Target("dir", str(tree), str(tree)), rec)
    return tree, rec, entry


def test_undoing_a_directory_keeps_the_work_it_overwrites(tmp_path):
    tree, rec, entry = _dir_entry(tmp_path)
    assert recovery.snapshot_before_restore(entry, rec) is None, "control: nothing changed"

    (tree / "keep.txt").write_text("v2 - work done after the snapshot\n")
    (tree / "new.txt").write_text("created later\n")
    kept = recovery.snapshot_before_restore(entry, rec)
    assert kept and kept["kind"] == "dir" and kept["target"] == str(tree)
    assert "undo" in kept["action"]
    assert not os.path.exists(os.path.join(kept["recovery_point"], "new.txt")), \
        "the overlay never touches a file created later, so it is not copied"

    assert recovery.restore(entry).ok
    assert (tree / "keep.txt").read_text() == "v1\n"                 # the undo happened
    assert recovery.restore(kept).ok
    assert (tree / "keep.txt").read_text() == "v2 - work done after the snapshot\n"


# --------------------------------------------------------------------------
# ELEV-MSG
# --------------------------------------------------------------------------

def test_setup_does_not_announce_a_lock_it_is_about_to_take(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(protect, "is_elevated", lambda: False)
    alone = protect.plan_protect(str(proj))
    assert any("will NOT be locked" in w for w in alone.warnings), "control: protect alone"
    via_setup = protect.plan_protect(str(proj), elevate=True)
    assert not any("will NOT be locked" in w for w in via_setup.warnings)
    assert any("UAC" in w for w in via_setup.warnings)
    assert "plan_protect(project, elevate=True)" in inspect.getsource(lifecycle.cmd_setup)
