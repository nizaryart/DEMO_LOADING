import argparse
import os
import sys
from pathlib import Path
import pytest

from demo_cli.config import Config
from demo_cli.decide import ALLOW, REVERSIBLE, ESCALATE, SUPERVISED
from demo_cli.guard import Guard, agent_directory
from demo_cli.recovery import load_entries
from demo_cli.cli import cmd_undo
from demo_cli.syscall_guard import available as syscall_available



def test_rm_two_files_reversible_one_group_restores_both(tmp_path):
    f1 = tmp_path / "a.txt"
    f2 = tmp_path / "b.txt"
    f1.write_text("hello a")
    f2.write_text("hello b")

    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate("rm a.txt b.txt")

    assert r.decision.decision == REVERSIBLE
    assert r.recovery_entry is not None
    assert r.group_id is not None

    entries = load_entries(cfg.recovery_dir)
    assert len(entries) == 2
    assert {e["group"] for e in entries} == {r.group_id}

    # Actually delete the files and undo
    f1.unlink()
    f2.unlink()
    assert not f1.exists() and not f2.exists()

    args = argparse.Namespace(id=r.group_id, root=str(tmp_path), target=None, no_presnapshot=False)
    assert cmd_undo(args) == 0

    assert f1.read_text() == "hello a"
    assert f2.read_text() == "hello b"


def test_backslash_rm_reversible(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("content")

    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate(r"\rm a.txt")

    assert r.decision.decision == REVERSIBLE
    assert r.recovery_entry is not None


def test_tee_truncating_reversible(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("content")

    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate("tee a.txt </dev/null")

    assert r.decision.decision == REVERSIBLE
    assert r.recovery_entry is not None


def test_mv_and_rm_reversible_captures_both_contents(tmp_path):
    f1 = tmp_path / "a.txt"
    f2 = tmp_path / "b.txt"
    f1.write_text("content a")
    f2.write_text("content b")

    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate("mv a.txt b.txt && rm b.txt")

    assert r.decision.decision == REVERSIBLE
    assert r.recovery_entry is not None

    entries = load_entries(cfg.recovery_dir)
    assert len(entries) == 2
    contents = {open(e["recovery_point"]).read() for e in entries}
    assert "content a" in contents
    assert "content b" in contents


def test_echo_and_rm_dir_reversible_captures_dir(tmp_path):
    d = tmp_path / "dir"
    d.mkdir()
    (d / "sub.txt").write_text("inside")

    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate("echo hi > new.txt && rm -rf dir")

    assert r.decision.decision == REVERSIBLE
    assert r.recovery_entry is not None

    entries = load_entries(cfg.recovery_dir)
    assert len(entries) == 1
    assert entries[0]["kind"] == "dir"


def test_echo_creates_new_file_is_allow(tmp_path):
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate("echo hi > new.txt")

    assert r.decision.decision == ALLOW
    assert r.recovery_entry is None


def test_select_1_rm_dir_captures_dir(tmp_path):
    d = tmp_path / "dir"
    d.mkdir()
    (d / "item.txt").write_text("data")

    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate("SELECT 1; rm -rf dir")

    assert r.decision.decision == REVERSIBLE
    assert r.recovery_entry is not None
    assert r.target.ref == str(d)


def test_rm_outside_project_escalates(tmp_path):
    outside = Path("/tmp/x")
    outside.mkdir(exist_ok=True)
    (outside / "file.txt").write_text("data")

    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate("rm -rf /tmp/x")

    assert r.decision.decision == ESCALATE
    assert r.recovery_entry is None


def test_psql_remote_database_escalates_with_remote_surface(tmp_path):
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate("psql postgres://db.example.com/app -c 'DELETE FROM t'")

    assert r.decision.decision == ESCALATE
    assert r.decision.surface == "remote_database"
    assert r.recovery_entry is None


def test_unknown_tool_falls_back_to_off_engine_path(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello")

    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        # unknown_tool is uncovered by engine -> falls back to today's path (ALLOW)
        r = g.evaluate("unknown_tool a.txt", can_supervise=True)
        assert r.decision.decision == ALLOW

        # where SYS1 applies on today's path: rm with unresolvable operand -> SUPERVISED
        if syscall_available():
            r2 = g.evaluate("rm $(cat list.txt)", can_supervise=True)
            assert r2.decision.decision == SUPERVISED


def test_engine_budget_overrun_falls_back_never_allow(tmp_path, monkeypatch):
    f = tmp_path / "a.txt"
    f.write_text("content")

    from demo_cli.engine.simulate import BudgetExceeded
    def fail_predict(*args, **kwargs):
        raise BudgetExceeded(0.0)

    monkeypatch.setattr("demo_cli.engine.predict", fail_predict)

    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate("rm a.txt")

    assert r.prediction is not None
    assert r.prediction.get("error") == "budget"
    # Off-engine path takes over for rm a.txt -> captures a.txt via text-only path, REVERSIBLE
    assert r.decision.decision == REVERSIBLE
    assert r.recovery_entry is not None


def test_powershell_command_unchanged(tmp_path):
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate("Remove-Item a.txt", dialect="powershell")

    assert r.prediction is not None
    assert r.prediction.get("skipped") == "powershell"
