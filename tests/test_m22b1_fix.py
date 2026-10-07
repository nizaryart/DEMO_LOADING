from __future__ import annotations

import json
from pathlib import Path

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


def test_1_rows(tmp_path: Path):
    fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "m22b1_fix"
    with open(fixtures_dir / "fix_rows_input.json") as f:
        inputs = json.load(f)
    with open(fixtures_dir / "expected_fix_rows.json") as f:
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
        assert ((r.prediction or {}).get("uncovered") or []) == exp["uncovered"], cmd

