"""M2.2b2b: gcloud, gsutil, az, azcopy and railway as engine rules.

The rows and their expected results are in tests/fixtures/m22b2b/ (measured
by ORCH on the prototype, on Linux and on Windows Python 3.14). Three rows are
SUPERVISED on a machine with the runtime net and ESCALATE without it - today's
path plus the net decides them - so for those the uncovered marker is the
check, the same on both systems.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from conftest import assert_restores
from demo_cli.config import Config
from demo_cli.guard import Guard, agent_directory

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "m22b2b"


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


def _evaluate(proj: Path, cmd: str):
    cfg = Config(project_root=str(proj), mode="enforce")
    with agent_directory(str(proj)):
        return Guard(cfg).evaluate(cmd, door="agent", can_supervise=True)


def test_1_rows(tmp_path: Path):
    rows = json.load(open(FIXTURES / "cloud2_rows_input.json"))
    expected = json.load(open(FIXTURES / "expected_cloud2_rows.json"))
    for idx, row in enumerate(rows):
        cmd = row["cmd"]
        exp = expected[cmd]
        proj = tmp_path / f"p_{idx}"
        _make_fixture(proj)
        r = _evaluate(proj, cmd)
        assert ((r.prediction or {}).get("uncovered") or []) == exp["uncovered"], cmd
        assert ((r.prediction or {}).get("remote") or {}) == exp["remote"], cmd
        assert (r.recovery_entry is not None) == exp["captured"], cmd
        if exp["decision"] == "SUPERVISED":
            continue        # decided by today's path + the runtime net: machine-dependent
        assert r.decision.decision == exp["decision"], cmd
        assert r.classification.nonrecoverable_surface == exp["surface"], cmd


def test_2_loaded_only_when_named(tmp_path: Path):
    code = (
        "import os, sys\n"
        "from demo_cli.config import Config\n"
        "from demo_cli.engine import predict\n"
        "cfg = Config(project_root=os.getcwd())\n"
        "for c in ('rm a.txt', 'aws s3 ls', 'kubectl get pods', 'ls -la'):\n"
        "    predict(c, cfg, budget_ms=10000)\n"
        "mods = lambda: sorted(m for m in sys.modules if m.split('.')[-1] in ('cloud2_ops', 'rules_cloud2'))\n"
        "print('before', mods())\n"
        "predict('gcloud compute instances list', cfg, budget_ms=10000)\n"
        "print('after', mods())\n"
    )
    (tmp_path / "a.txt").write_text("a")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    out = subprocess.run([sys.executable, "-c", code], cwd=str(tmp_path), env=env,
                         capture_output=True, text=True, timeout=120).stdout
    assert "before []" in out
    assert "after ['demo_cli.engine.cloud2_ops', 'demo_cli.engine.rules_cloud2']" in out


CAPTURES = [
    ("gcloud storage cp gs://b/a.txt a.txt", {"a.txt": b"A"}),
    ("gcloud storage rsync gs://b sub --recursive --delete-unmatched-destination-objects",
     {"sub/s.txt": b"s"}),
    ("gsutil rsync -d gs://b sub", {"sub/s.txt": b"s"}),
    ("gsutil cp gs://b/a.txt a.txt", {"a.txt": b"A"}),
    ("az storage blob download -c c -n x -f a.txt", {"a.txt": b"A"}),
    ("az storage blob download-batch -s c -d sub --overwrite", {"sub/s.txt": b"s"}),
    ("azcopy copy https://a.blob.core.windows.net/c/a.txt a.txt", {"a.txt": b"A"}),
    ("azcopy copy https://a.blob.core.windows.net/c sub --recursive", {"sub/s.txt": b"s"}),
    ("azcopy sync https://a.blob.core.windows.net/c sub --delete-destination=true",
     {"sub/s.txt": b"s"}),
]


def test_3_captures_restore(tmp_path: Path):
    """Every REVERSIBLE row: the local files it may lose come back byte-exact."""
    expected = json.load(open(FIXTURES / "expected_cloud2_rows.json"))
    assert sorted(c for c, e in expected.items() if e["decision"] == "REVERSIBLE") == \
        sorted(c for c, _ in CAPTURES), "the list below is every REVERSIBLE row"
    for idx, (cmd, files) in enumerate(CAPTURES):
        proj = tmp_path / f"cap_{idx}"
        _make_fixture(proj)
        r = _evaluate(proj, cmd)
        assert r.decision.decision == "REVERSIBLE", cmd
        assert r.recovery_entry is not None, cmd
        assert_restores(r.recovery_entry, str(proj), files)
