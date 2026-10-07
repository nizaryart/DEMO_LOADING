from __future__ import annotations

import json
import os
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


# ------------------------------------------------------------------------------
# Test 1: Infra rows
# ------------------------------------------------------------------------------

def test_1_rows(tmp_path: Path):
    fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "m22b1"
    with open(fixtures_dir / "infra_rows_input.json") as f:
        inputs = json.load(f)
    with open(fixtures_dir / "expected_infra_rows.json") as f:
        expected = json.load(f)

    for idx, item in enumerate(inputs):
        cmd = item["cmd"]
        exp = expected[cmd]

        proj = tmp_path / f"p_{idx}"
        _make_fixture(proj)

        cfg = Config(project_root=str(proj), mode="enforce")
        g = Guard(cfg)
        with agent_directory(str(proj)):
            r = g.evaluate(cmd, door="agent", can_supervise=True)

        assert r.decision.decision == exp["decision"], cmd
        assert r.classification.nonrecoverable_surface == exp["surface"], cmd
        captured = r.recovery_entry is not None
        assert captured == exp["captured"], cmd
        assert ((r.prediction or {}).get("remote") or {}) == exp["remote"], cmd


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
        "infra = lambda: sorted(m for m in sys.modules if m.split('.')[-1] in ('infra_ops', 'rules_infra'))\n"
        "print('before', infra())\n"
        "predict('kubectl get pods', cfg, budget_ms=10000)\n"
        "print('after', infra())\n"
    )
    (tmp_path / "a.txt").write_text("a")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    out = subprocess.run([sys.executable, "-c", code], cwd=str(tmp_path), env=env,
                         capture_output=True, text=True, timeout=60).stdout
    assert "before []" in out
    assert "after ['demo_cli.engine.infra_ops', 'demo_cli.engine.rules_infra']" in out


# ------------------------------------------------------------------------------
# Test 3: Allowed is named
# ------------------------------------------------------------------------------

def test_3_allowed_is_named(tmp_path: Path):
    proj = tmp_path / "p_k8s"
    _make_fixture(proj)
    cfg = Config(project_root=str(proj), mode="enforce")
    g = Guard(cfg)
    with agent_directory(str(proj)):
        r = g.evaluate("kubectl scale deploy api --replicas=3", door="agent", can_supervise=True)
    assert r.decision.decision == "ALLOW"
    assert "Recorded and allowed: cluster-workload:current/default" in r.decision.reason

    proj2 = tmp_path / "p_tf"
    _make_fixture(proj2)
    cfg2 = Config(project_root=str(proj2), mode="enforce")
    g2 = Guard(cfg2)
    with agent_directory(str(proj2)):
        r2 = g2.evaluate("terraform workspace new dev", door="agent", can_supervise=True)
    assert r2.decision.decision == "ALLOW"
    assert "Recorded and allowed: iac:terraform" in r2.decision.reason


# ------------------------------------------------------------------------------
# Test 4: Captures
# ------------------------------------------------------------------------------

def test_4_captures(tmp_path: Path):
    cases = [
        ("terraform plan -out=a.txt", {"a.txt": b"A"}),
        ("terraform init -upgrade", {".terraform.lock.hcl": b"# lock\n"}),
        ("terraform fmt", {"main.tf": b'resource "x" "y" {}\n', "vars.tfvars": b"a = 1\n"}),
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
# Test 5: No target snapshot beside an escalation
# ------------------------------------------------------------------------------

def test_5_no_target_snapshot_beside_an_escalation(tmp_path: Path):
    for idx, cmd in enumerate(["git push --force origin main", "kubectl delete pod x", "terraform destroy"]):
        proj = tmp_path / f"esc_{idx}"
        _make_fixture(proj)
        cfg = Config(project_root=str(proj), mode="enforce")
        g = Guard(cfg)
        with agent_directory(str(proj)):
            r = g.evaluate(cmd, target_path=str(proj / "a.txt"))
        assert r.decision.decision == "ESCALATE", cmd
        assert r.recovery_entry is None, cmd
        idx_file = proj / ".demo_cli" / "recovery" / "index.jsonl"
        assert not idx_file.exists() or idx_file.read_text().strip() == "", cmd

    # control: touch b.txt with the same target
    proj_ctrl = tmp_path / "ctrl"
    _make_fixture(proj_ctrl)
    cfg_ctrl = Config(project_root=str(proj_ctrl), mode="enforce")
    g_ctrl = Guard(cfg_ctrl)
    with agent_directory(str(proj_ctrl)):
        r_ctrl = g_ctrl.evaluate("touch b.txt", target_path=str(proj_ctrl / "a.txt"))
    assert r_ctrl.decision.decision == "REVERSIBLE"
    assert r_ctrl.recovery_entry is not None


# ------------------------------------------------------------------------------
# Test 6: Hints
# ------------------------------------------------------------------------------

def test_6_hints(tmp_path: Path):
    from demo_cli import policy

    proj = tmp_path / "hint_k8s"
    _make_fixture(proj)
    cfg = Config(project_root=str(proj), mode="enforce")
    g = Guard(cfg)
    with agent_directory(str(proj)):
        r = g.evaluate("kubectl drain node1", door="agent", can_supervise=True)
    assert r.decision.decision == "ESCALATE"
    assert r.decision.surface == "cluster_availability"
    assert policy.RECOVERY_HINTS["cluster_availability"] in "\n".join(r.decision.next_steps)

    proj2 = tmp_path / "hint_pulumi"
    _make_fixture(proj2)
    cfg2 = Config(project_root=str(proj2), mode="enforce")
    g2 = Guard(cfg2)
    with agent_directory(str(proj2)):
        r2 = g2.evaluate("pulumi destroy", door="agent", can_supervise=True)
    assert r2.decision.decision == "ESCALATE"
    assert r2.decision.surface == "infra_destroy"
    assert policy.RECOVERY_HINTS["infra_destroy"] in "\n".join(r2.decision.next_steps)


# ------------------------------------------------------------------------------
# Test 7: Payload lines are not claimed
# ------------------------------------------------------------------------------

def test_7_payload_lines_are_not_claimed(tmp_path: Path):
    fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "m22b1"
    with open(fixtures_dir / "payload_rows_input.json") as f:
        inputs = json.load(f)
    with open(fixtures_dir / "expected_payload_rows.json") as f:
        expected = json.load(f)

    for idx, item in enumerate(inputs):
        cmd = item["cmd"]
        exp = expected[cmd]

        proj = tmp_path / f"payload_{idx}"
        _make_fixture(proj)

        cfg = Config(project_root=str(proj), mode="enforce")
        g = Guard(cfg)
        with agent_directory(str(proj)):
            r = g.evaluate(cmd, door="agent", can_supervise=True)

        prediction = r.prediction or {}
        assert (prediction.get("uncovered") or []) == exp["uncovered"], cmd
        assert (prediction.get("remote") or {}) == exp["remote"], cmd

        # Two payload rows are SUPERVISED on machines with a runtime net (Linux),
        # but ESCALATE on machines without one (Windows); for those two, the
        # uncovered assert above confirms the engine left them to the old path.
        if exp["decision"] != "SUPERVISED":
            assert r.decision.decision == exp["decision"], cmd


