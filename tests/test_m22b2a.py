from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import assert_restores
from demo_cli.config import Config
from demo_cli.guard import Guard, agent_directory


def _make_fixture(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)
    (p / "a.txt").write_bytes(b"A")
    (p / "main.tf").write_bytes(b'resource "x" "y" {}\n')
    (p / "vars.tfvars").write_bytes(b"a = 1\n")
    (p / ".terraform.lock.hcl").write_bytes(b"# lock\n")
    (p / "k8s").mkdir(parents=True, exist_ok=True)
    (p / "k8s" / "dep.yaml").write_bytes(b"kind: Deployment\n")
    (p / "infra").mkdir(parents=True, exist_ok=True)
    (p / "infra" / "main.tf").write_bytes(b"# infra\n")
    (p / "ids.txt").write_bytes(b"1\n")
    (p / "sub").mkdir(parents=True, exist_ok=True)
    (p / "sub" / "s.txt").write_bytes(b"s")
    (p / "t.yml").write_bytes(b"x: 1\n")


# `C:` is an rclone remote named "C" on Linux (VERIFIED) and a drive on Windows,
# so these two rows have one answer per OS.
_PLATFORM_ROWS = frozenset({"rclone purge C:/x", "rclone purge c:x"})


# ------------------------------------------------------------------------------
# Test 1: Cloud rows
# ------------------------------------------------------------------------------

def test_1_rows(tmp_path: Path):
    fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "m22b2a"
    with open(fixtures_dir / "cloud_rows_input.json") as f:
        inputs = json.load(f)
    with open(fixtures_dir / "expected_cloud_rows.json") as f:
        expected = json.load(f)

    for idx, item in enumerate(inputs):
        cmd = item["cmd"]
        exp = expected[cmd]
        if cmd in _PLATFORM_ROWS:
            continue                    # decided per OS: test_5a and test_5b

        proj = tmp_path / f"p_{idx}"
        _make_fixture(proj)

        cfg = Config(project_root=str(proj), mode="enforce")
        g = Guard(cfg)
        with agent_directory(str(proj)):
            r = g.evaluate(cmd, door="agent", can_supervise=True)

        assert r.classification.nonrecoverable_surface == exp["surface"], cmd
        captured = r.recovery_entry is not None
        assert captured == exp["captured"], cmd
        assert ((r.prediction or {}).get("remote") or {}) == exp["remote"], cmd
        assert ((r.prediction or {}).get("uncovered") or []) == exp["uncovered"], cmd

        if exp["decision"] != "SUPERVISED":
            assert r.decision.decision == exp["decision"], cmd
        else:
            # Two rows are SUPERVISED (aws ec2 run-instances ... --user-data ... and mc rm --recursive --force sub):
            # today's path plus the runtime net decides them, which depends on the machine.
            # For those two the uncovered / remote asserts above are the check.
            pass


# ------------------------------------------------------------------------------
# Test 2: Loaded only when named
# ------------------------------------------------------------------------------

def test_2_loaded_only_when_named(tmp_path: Path):
    code = (
        "import os, sys\n"
        "from demo_cli.config import Config\n"
        "from demo_cli.engine import predict\n"
        "cfg = Config(project_root=os.getcwd())\n"
        "for c in ('rm a.txt', 'cp a.txt b.txt', 'echo x > a.txt', 'ls -la'):\n"
        "    predict(c, cfg, budget_ms=10000)\n"
        "cloud = lambda: sorted(m for m in sys.modules if m.split('.')[-1] in ('cloud_ops', 'rules_cloud'))\n"
        "print('before', cloud())\n"
        "predict('aws s3 ls', cfg, budget_ms=10000)\n"
        "print('after', cloud())\n"
    )
    (tmp_path / "a.txt").write_text("a")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    out = subprocess.run([sys.executable, "-c", code], cwd=str(tmp_path), env=env,
                         capture_output=True, text=True, timeout=60).stdout
    assert "before []" in out
    assert "after ['demo_cli.engine.cloud_ops', 'demo_cli.engine.rules_cloud']" in out


# ------------------------------------------------------------------------------
# Test 3: Sync delete restores
# ------------------------------------------------------------------------------

def test_3_sync_delete_restores(tmp_path: Path):
    # 1. aws s3 sync s3://b sub --delete: REVERSIBLE; delete sub entirely and assert_restores brings sub/s.txt back
    proj = tmp_path / "sync_del"
    _make_fixture(proj)
    cfg = Config(project_root=str(proj), mode="enforce")
    g = Guard(cfg)
    with agent_directory(str(proj)):
        r = g.evaluate("aws s3 sync s3://b sub --delete", door="agent", can_supervise=True)
    assert r.decision.decision == "REVERSIBLE"
    assert r.recovery_entry is not None
    shutil.rmtree(proj / "sub")
    assert not (proj / "sub").exists()
    assert_restores(r.recovery_entry, str(proj), {"sub/s.txt": b"s"})

    # 2. aws s3 sync sub s3://b --delete: ESCALATE, surface object_storage
    proj2 = tmp_path / "sync_up"
    _make_fixture(proj2)
    cfg2 = Config(project_root=str(proj2), mode="enforce")
    g2 = Guard(cfg2)
    with agent_directory(str(proj2)):
        r2 = g2.evaluate("aws s3 sync sub s3://b --delete", door="agent", can_supervise=True)
    assert r2.decision.decision == "ESCALATE"
    assert r2.classification.nonrecoverable_surface == "object_storage"

    # 3. aws s3 sync s3://b . --delete: ESCALATE (the project root cannot be captured whole)
    proj3 = tmp_path / "sync_root"
    _make_fixture(proj3)
    cfg3 = Config(project_root=str(proj3), mode="enforce")
    g3 = Guard(cfg3)
    with agent_directory(str(proj3)):
        r3 = g3.evaluate("aws s3 sync s3://b . --delete", door="agent", can_supervise=True)
    assert r3.decision.decision == "ESCALATE"


# ------------------------------------------------------------------------------
# Test 4: Captures
# ------------------------------------------------------------------------------

def test_4_captures(tmp_path: Path):
    cases = [
        ("aws s3api get-object --bucket b --key k a.txt", {"a.txt": b"A"}),
        ("aws s3 cp s3://b/a.txt a.txt", {"a.txt": b"A"}),
        ("aws s3 cp s3://b/ sub --recursive", {"sub/s.txt": b"s"}),
        ("s3cmd get --force s3://b/a.txt a.txt", {"a.txt": b"A"}),
        ("s3cmd sync s3://b/ sub/ --delete-removed", {"sub/s.txt": b"s"}),
        ("rclone sync remote:b sub", {"sub/s.txt": b"s"}),
        ("rclone delete sub", {"sub/s.txt": b"s"}),
        ("mc rm --recursive --force ./sub", {"sub/s.txt": b"s"}),
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
# Test 5: a one-letter rclone remote is a remote on Linux, a drive on Windows
# ------------------------------------------------------------------------------

def _evaluate(proj: Path, cmd: str):
    cfg = Config(project_root=str(proj), mode="enforce")
    with agent_directory(str(proj)):
        return Guard(cfg).evaluate(cmd, door="agent", can_supervise=True)


@pytest.mark.skipif(os.name == "nt", reason="on Windows a one-letter name is a drive")
def test_5a_one_letter_remote_on_posix(tmp_path: Path):
    expected = json.load(open(Path(__file__).resolve().parent / "fixtures" / "m22b2a"
                              / "expected_cloud_rows.json"))
    for idx, cmd in enumerate(sorted(_PLATFORM_ROWS)):
        exp = expected[cmd]
        proj = tmp_path / f"p_{idx}"
        _make_fixture(proj)
        r = _evaluate(proj, cmd)
        assert r.decision.decision == exp["decision"], cmd
        assert r.classification.nonrecoverable_surface == exp["surface"], cmd
        assert ((r.prediction or {}).get("remote") or {}) == exp["remote"], cmd


@pytest.mark.skipif(os.name != "nt", reason="a drive letter exists only on Windows")
def test_5b_drive_letter_on_windows(tmp_path: Path):
    for idx, cmd in enumerate(sorted(_PLATFORM_ROWS)):
        proj = tmp_path / f"p_{idx}"
        _make_fixture(proj)
        r = _evaluate(proj, cmd)
        assert r.decision.decision == "ALLOW", cmd          # C:\x does not exist
        assert ((r.prediction or {}).get("remote") or {}) == {}, cmd
    # The control: a drive path INTO the project is a local purge, captured.
    proj = tmp_path / "drive"
    _make_fixture(proj)
    r = _evaluate(proj, "rclone purge " + str(proj / "sub").replace("\\", "/"))
    assert r.decision.decision == "REVERSIBLE"
    assert ((r.prediction or {}).get("remote") or {}) == {}
    assert_restores(r.recovery_entry, str(proj), {"sub/s.txt": b"s"})
