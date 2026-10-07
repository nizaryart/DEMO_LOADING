"""M2.2b3 (data stores): redis-cli, mongosh / mongo, dropdb / pg_restore /
pg_dump, mysqladmin, sqlcmd as engine rules.

Rows and expected results in tests/fixtures/m22b3_datastores/, measured by
ORCH on the prototype on Linux and Windows Python 3.14. One row is SUPERVISED
on a machine with the runtime net and ESCALATE without it (today's path
decides it), so for it the uncovered / remote check is the test.
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

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "m22b3_datastores"
MODULES = ("datastore_ops", "rules_datastore")
CONTROL = "redis-cli GET k"


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
    rows = json.load(open(FIXTURES / "rows_input.json"))
    expected = json.load(open(FIXTURES / "expected_rows.json"))
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
        "for c in (\"rm a.txt\", \"aws s3 ls\", \"gcloud compute instances list\", \"ls -la\"):\n"
        "    predict(c, cfg, budget_ms=10000)\n"
        f"mods = lambda: sorted(m for m in sys.modules if m.split(\".\")[-1] in {MODULES!r})\n"
        "print(\"before\", mods())\n"
        f"predict({CONTROL!r}, cfg, budget_ms=10000)\n"
        "print(\"after\", mods())\n"
    )
    (tmp_path / "a.txt").write_text("a")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    out = subprocess.run([sys.executable, "-c", code], cwd=str(tmp_path), env=env,
                         capture_output=True, text=True, timeout=120).stdout
    assert "before []" in out
    assert "after " + str(sorted("demo_cli.engine." + m for m in MODULES)) in out


CAPTURES = [
    ("redis-cli --rdb a.txt", {"a.txt": b"A"}),
    ("pg_dump -Fd -f sub mydb", {"sub/s.txt": b"s"}),
]


def test_3_captures_restore(tmp_path: Path):
    """Every REVERSIBLE row: the local files it writes over come back byte-exact."""
    expected = json.load(open(FIXTURES / "expected_rows.json"))
    assert sorted(c for c, e in expected.items() if e["decision"] == "REVERSIBLE") == \
        sorted(c for c, _ in CAPTURES), "the list below is every REVERSIBLE row"
    for idx, (cmd, files) in enumerate(CAPTURES):
        proj = tmp_path / f"cap_{idx}"
        _make_fixture(proj)
        r = _evaluate(proj, cmd)
        assert r.decision.decision == "REVERSIBLE", cmd
        assert r.recovery_entry is not None, cmd
        assert_restores(r.recovery_entry, str(proj), files)
