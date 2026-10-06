from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from conftest import assert_restores
from demo_cli.config import Config
from demo_cli.engine.simulate import simulate
from demo_cli.guard import Guard, agent_directory
from demo_cli import syscall_guard


def _make_fixture(p: Path) -> None:
    (p / ".git" / "objects").mkdir(parents=True, exist_ok=True)
    (p / ".git" / "HEAD").write_bytes(b"ref: refs/heads/main\n")
    (p / ".git" / "objects" / "x").write_bytes(b"")
    (p / "a.txt").write_bytes(b"A")
    (p / "src").mkdir(parents=True, exist_ok=True)
    (p / "src" / "m.py").write_bytes(b"m")
    (p / "src" / "n.py").write_bytes(b"n")
    (p / "wt").mkdir(parents=True, exist_ok=True)
    (p / "wt" / "f.txt").write_bytes(b"w")
    (p / "ids.txt").write_bytes(b"1\n")


# ------------------------------------------------------------------------------
# Test 1: Inventory rows
# ------------------------------------------------------------------------------

def test_1_inventory_rows(tmp_path: Path):
    ref_dir = Path(__file__).resolve().parent / "fixtures" / "m22a"
    with open(ref_dir / "git_rows_input.json") as f:
        inputs = json.load(f)
    with open(ref_dir / "expected_git_rows.json") as f:
        expected = json.load(f)

    for idx, item in enumerate(inputs):
        cmd = item["cmd"]
        exp = expected[cmd]

        if exp["decision"] == "SUPERVISED":
            continue  # The one net-dependent row is covered by test_5a and test_5b

        proj = tmp_path / f"p_{idx}"
        _make_fixture(proj)

        cfg = Config(project_root=str(proj), mode="enforce")
        g = Guard(cfg)
        with agent_directory(str(proj)):
            r = g.evaluate(cmd, door="agent", can_supervise=True)

        assert r.decision.decision == exp["decision"], cmd
        captured = r.recovery_entry is not None
        assert captured == exp["captured"], cmd


# ------------------------------------------------------------------------------
# Test 2: Safety property
# ------------------------------------------------------------------------------

def test_2_safety_property(tmp_path: Path):
    from demo_cli.engine.git_ops import git as _git_op

    proj = tmp_path / "safety"
    _make_fixture(proj)
    cfg = Config(project_root=str(proj), mode="enforce")
    g = Guard(cfg)

    # 1. An unlisted git subcommand reports uncovered and leaves decision to old path
    imp = simulate("git frobnicate x", cwd=str(proj))
    assert imp.uncovered == ["git frobnicate"]
    with agent_directory(str(proj)):
        r = g.evaluate("git frobnicate x", door="agent", can_supervise=True)
    assert r.prediction.get("uncovered") == ["git frobnicate"]
    assert r.decision.decision == "ALLOW"

    # 2. git config with a write reports uncovered
    imp_cfg = simulate("git config core.hooksPath /tmp/h", cwd=str(proj))
    assert imp_cfg.uncovered == ["git config"]
    with agent_directory(str(proj)):
        r_cfg = g.evaluate("git config core.hooksPath /tmp/h", door="agent", can_supervise=True)
    assert r_cfg.prediction.get("uncovered") == ["git config"]
    assert r_cfg.decision.decision == "ALLOW"


# ------------------------------------------------------------------------------
# Test 3: Allowed is named
# ------------------------------------------------------------------------------

def test_3_allowed_is_named(tmp_path: Path):
    proj = tmp_path / "allowed"
    _make_fixture(proj)
    cfg = Config(project_root=str(proj), mode="enforce")
    g = Guard(cfg)
    with agent_directory(str(proj)):
        r = g.evaluate("git branch -d feat", door="agent", can_supervise=True)
    assert r.decision.decision == "ALLOW"
    assert "Recorded and allowed" in r.decision.reason
    assert "vcs-local:branch" in r.decision.reason
    assert "git reflog" in r.decision.reason


# ------------------------------------------------------------------------------
# Test 4: Captures
# ------------------------------------------------------------------------------

def test_4_captures(tmp_path: Path):
    cases = [
        ("git restore src/m.py", {"src/m.py": b"m"}),
        ("git worktree remove --force wt", {"wt/f.txt": b"w"}),
        ("git rm -r src", {"src/m.py": b"m", "src/n.py": b"n"}),
    ]

    for idx, (cmd, expected_files) in enumerate(cases):
        proj = tmp_path / f"cap_{idx}"
        _make_fixture(proj)
        cfg = Config(project_root=str(proj), mode="enforce")
        g = Guard(cfg)
        with agent_directory(str(proj)):
            r = g.evaluate(cmd, door="agent", can_supervise=True)
        assert r.decision.decision == "REVERSIBLE", cmd
        assert r.recovery_entry is not None, cmd
        assert_restores(r.recovery_entry, str(proj), expected_files)


# ------------------------------------------------------------------------------
# Test 5: The one net-dependent row
# ------------------------------------------------------------------------------

@pytest.mark.skipif(not syscall_guard.available(), reason="requires syscall guard")
def test_5a_net_row_with_the_net(tmp_path: Path):
    proj = tmp_path / "net_row"
    _make_fixture(proj)
    cfg = Config(project_root=str(proj), mode="enforce")
    g = Guard(cfg)
    with agent_directory(str(proj)):
        r = g.evaluate("git config --global alias.st '!rm -rf ~'", door="agent", can_supervise=True)
    assert r.decision.decision == "SUPERVISED"


@pytest.mark.skipif(syscall_guard.available(), reason="requires environment without syscall guard")
def test_5b_net_row_without_a_net(tmp_path: Path):
    proj = tmp_path / "net_row"
    _make_fixture(proj)
    cfg = Config(project_root=str(proj), mode="enforce")
    g = Guard(cfg)
    with agent_directory(str(proj)):
        r = g.evaluate("git config --global alias.st '!rm -rf ~'", door="agent", can_supervise=True)
    assert r.decision.decision == "ESCALATE"


