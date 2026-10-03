from __future__ import annotations

import os
import pytest
from types import SimpleNamespace
from demo_cli import cli, doctor
from demo_cli.protection import THREAT_MODEL, Facts, rows


def test_protection_rows_cases():
    # Case 1: Linux + claude_code + syscall_guard
    f1 = Facts(os_name="posix", agents=("claude_code",), syscall_guard=True, checkpoint_enabled=False)
    r1 = rows(f1)
    assert len(r1) == 3
    assert r1[0] == ("ok", "threat model", THREAT_MODEL)
    assert r1[1] == (
        "ok",
        "protection: claude_code",
        "runs under the syscall guard (each destroyed file backed up at the moment of destruction)",
    )
    assert r1[2] == ("ok", "remote changes", "always stopped for review: no local copy can undo them")

    # Case 2: Linux + codex (checkpoint disabled)
    f2 = Facts(os_name="posix", agents=("codex",), checkpoint_enabled=False)
    r2 = rows(f2)
    assert r2[1] == (
        "warn",
        "protection: codex",
        "Codex's hook can only deny, so it cannot be supervised: escalated for review",
    )
    assert "cannot be supervised" in r2[1][2]

    # Case 3: Linux + codex (checkpoint enabled)
    f3 = Facts(os_name="posix", agents=("codex",), checkpoint_enabled=True)
    r3 = rows(f3)
    assert r3[1] == (
        "warn",
        "protection: codex",
        "Codex's hook can only deny, so it cannot be supervised: whole-workspace checkpoint",
    )

    # Case 4: Linux + claude_code without syscall_guard (checkpoint disabled)
    f4 = Facts(os_name="posix", agents=("claude_code",), syscall_guard=False, checkpoint_enabled=False)
    r4 = rows(f4)
    assert r4[1] == ("warn", "protection: claude_code", "cannot be supervised: escalated for review")
    assert "cannot be supervised" in r4[1][2]

    # Case 5: Linux + claude_code without syscall_guard (checkpoint enabled)
    f5 = Facts(os_name="posix", agents=("claude_code",), syscall_guard=False, checkpoint_enabled=True)
    r5 = rows(f5)
    assert r5[1] == ("warn", "protection: claude_code", "cannot be supervised: whole-workspace checkpoint")

    # Case 6: Windows + mount_running is True
    f6 = Facts(os_name="nt", agents=("claude_code",), mount_running=True)
    r6 = rows(f6)
    assert r6[1] == (
        "ok",
        "protection: claude_code",
        "covered by the demo_cli filesystem mount; PowerShell commands are judged by text rules only",
    )
    assert "covered by the demo_cli filesystem mount" in r6[1][2]
    assert "PowerShell commands are judged by text rules only" in r6[1][2]

    # Case 7: Windows + mount_running not True (checkpoint disabled)
    f7 = Facts(os_name="nt", agents=("claude_code",), mount_running=False, checkpoint_enabled=False)
    r7 = rows(f7)
    assert r7[1] == (
        "warn",
        "protection: claude_code",
        "NOT covered: the filesystem mount is not running (run demo_cli setup / mount), escalated for review; PowerShell commands are judged by text rules only",
    )
    assert "NOT covered" in r7[1][2]
    assert "PowerShell commands are judged by text rules only" in r7[1][2]

    # Case 8: Windows + mount_running not True (checkpoint enabled)
    f8 = Facts(os_name="nt", agents=("claude_code",), mount_running=False, checkpoint_enabled=True)
    r8 = rows(f8)
    assert r8[1] == (
        "warn",
        "protection: claude_code",
        "NOT covered: the filesystem mount is not running (run demo_cli setup / mount), whole-workspace checkpoint; PowerShell commands are judged by text rules only",
    )
    assert "NOT covered" in r8[1][2]
    assert "PowerShell commands are judged by text rules only" in r8[1][2]


def test_doctor_threat_model_output(tmp_path, capsys):
    doctor.cmd_doctor(SimpleNamespace(root=str(tmp_path)))
    out = capsys.readouterr().out
    assert "threat model" in out
    assert "demo_cli protects against an agent's MISTAKES" in out


def test_status_protection_heading(tmp_path, capsys):
    cli.cmd_status(SimpleNamespace(root=str(tmp_path)))
    out = capsys.readouterr().out
    assert "Protection" in out


def test_checkpoint_restore_note(tmp_path, capsys):
    from demo_cli import checkpoint, config, recovery, render

    # Create dummy project file
    dummy = tmp_path / "hello.txt"
    dummy.write_text("content", encoding="utf-8")

    cfg = config.Config(project_root=str(tmp_path), checkpoint={"enabled": True})
    res = checkpoint.capture(cfg, "rm hello.txt")
    assert res.ok
    assert res.entry is not None
    assert res.entry.get("scope") == "checkpoint"

    # Restoring checkpoint prints CHECKPOINT_UNDO_NOTE
    render.render_restore(res.entry, True, "1.0")
    out = capsys.readouterr().out
    assert recovery.CHECKPOINT_UNDO_NOTE in out

    # Control: an ordinary file snapshot does NOT print CHECKPOINT_UNDO_NOTE
    t = recovery.Target("file", str(dummy), str(dummy))
    normal_entry = recovery.snapshot(t, str(tmp_path / ".recovery"), "snapshot", action="rm hello.txt")
    assert normal_entry is not None
    assert normal_entry.get("scope") is None
    render.render_restore(normal_entry, True, "1.0")
    out_ctrl = capsys.readouterr().out
    assert recovery.CHECKPOINT_UNDO_NOTE not in out_ctrl


def test_postgres_capture_reason_and_restore_note(tmp_path, monkeypatch, capsys):
    from demo_cli import config, guard, recovery, render
    from demo_cli.decide import REVERSIBLE

    fake_entry = {
        "id": "pg123",
        "kind": "postgres",
        "target": "postgres://localhost/mydb",
        "recovery_point": str(tmp_path / "pg.dump"),
        "ts": 123456789.0,
        "action": "DELETE FROM t",
    }

    def fake_snapshot_set(targets, *args, **kwargs):
        return {
            "id": "pg123",
            "group": "pg123",
            "kind": "postgres",
            "target": targets[0].ref,
            "recovery_point": str(tmp_path / "pg.dump"),
            "count": len(targets),
            "entries": [fake_entry],
        }

    monkeypatch.setattr(recovery, "snapshot_set", fake_snapshot_set)

    cfg = config.Config(project_root=str(tmp_path), mode="enforce")
    g = guard.Guard(config=cfg)

    with guard.agent_directory(str(tmp_path)):
        r = g.evaluate("psql postgres://localhost/mydb -c 'DELETE FROM t'")
        assert r.decision.decision == REVERSIBLE
        assert recovery.PG_UNDO_LIMITS in r.decision.reason

    # render_restore of a postgres entry contains PG_UNDO_LIMITS
    render.render_restore(fake_entry, True, "1.0")
    out = capsys.readouterr().out
    assert recovery.PG_UNDO_LIMITS in out


def test_group_restore_count(capsys):
    from demo_cli import render

    # Set dictionary (from snapshot_set)
    set_entry = {
        "id": "grp1",
        "kind": "set",
        "target": "3 targets",
        "recovery_point": "fake.bak",
        "count": 3,
        "entries": [
            {"id": "1", "kind": "file", "target": "a", "recovery_point": "p1"},
            {"id": "2", "kind": "file", "target": "b", "recovery_point": "p2"},
            {"id": "3", "kind": "file", "target": "c", "recovery_point": "p3"},
        ],
    }
    render.render_restore(set_entry, True, "1.0")
    out = capsys.readouterr().out
    assert "restored 3" in out

    # List of 3 entries
    entries_list = [
        {"id": "1", "kind": "file", "target": "a", "recovery_point": "p1"},
        {"id": "2", "kind": "file", "target": "b", "recovery_point": "p2"},
        {"id": "3", "kind": "file", "target": "c", "recovery_point": "p3"},
    ]
    render.render_restore(entries_list, True, "1.0")
    out2 = capsys.readouterr().out
    assert "restored 3" in out2


# --------------------------------------------------------------------------
# Part T / ORCH 030: Git Bash path forms on Windows
# --------------------------------------------------------------------------

@pytest.mark.skipif(os.name != "nt", reason="Git Bash path forms exist only on Windows")
def test_git_bash_forward_slash_path_is_reversible(tmp_path):
    from demo_cli.config import Config
    from demo_cli.guard import Guard
    from demo_cli.decide import REVERSIBLE
    db = tmp_path / "data.db"
    content = b"header and payload"
    db.write_bytes(content)
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    fwd = db.as_posix()
    r = g.evaluate(f"rm {fwd}")
    assert r.decision.decision == REVERSIBLE
    assert_restores(r.recovery_entry, tmp_path, {"data.db": content})


@pytest.mark.skipif(os.name != "nt", reason="Git Bash path forms exist only on Windows")
def test_git_bash_single_quoted_backslash_path_is_reversible(tmp_path):
    from demo_cli.config import Config
    from demo_cli.guard import Guard
    from demo_cli.decide import REVERSIBLE
    db = tmp_path / "data.db"
    content = b"header and payload"
    db.write_bytes(content)
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    r = g.evaluate(f"rm '{db}'")
    assert r.decision.decision == REVERSIBLE
    assert_restores(r.recovery_entry, tmp_path, {"data.db": content})


@pytest.mark.skipif(os.name != "nt", reason="Git Bash path forms exist only on Windows")
def test_git_bash_msys_path_is_reversible(tmp_path):
    from demo_cli.config import Config
    from demo_cli.guard import Guard
    from demo_cli.decide import REVERSIBLE
    db = tmp_path / "data.db"
    content = b"header and payload"
    db.write_bytes(content)
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    drive = db.drive.rstrip(":").lower()
    msys = f"/{drive}{db.as_posix()[len(db.drive):]}"
    r = g.evaluate(f"rm {msys}")
    assert r.decision.decision == REVERSIBLE
    assert_restores(r.recovery_entry, tmp_path, {"data.db": content})


@pytest.mark.skipif(os.name != "nt", reason="Git Bash path forms exist only on Windows")
def test_git_bash_unquoted_backslash_path_is_allowed(tmp_path):
    from demo_cli.config import Config
    from demo_cli.guard import Guard
    from demo_cli.decide import ALLOW
    db = tmp_path / "data.db"
    content = b"header and payload"
    db.write_bytes(content)
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    # Per ORCH 030: bash strips the backslashes, the target does not exist, so nothing is destroyed -> ALLOW
    r = g.evaluate(f"rm {db}")
    assert r.decision.decision == ALLOW
    assert db.read_bytes() == content


