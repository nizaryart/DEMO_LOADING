"""M2.2b4a: what leaves the machine - HTTP clients (curl, wget, httpie, xh),
gh, mail, ssh / scp / sftp and package publishing - as engine rules, and
ruling (b): code run on a NAMED surface follows that surface's ask channel
row instead of fetch-and-run's deny.

Rows and expected results in tests/fixtures/m22b4a/, measured by ORCH on the
prototype on Linux and Windows Python 3.14. Eight rows are SUPERVISED on a
machine with the runtime net and ESCALATE without it (today's path decides
them: installs, and an accidental-text comment), so for those the uncovered /
remote fields are the check.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from demo_cli.config import Config
from demo_cli.guard import Guard, agent_directory

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "m22b4b2"
MODULES = ("saas_ops", "saas_data", "rules_saas")
CONTROL = "liquibase status"     # loads saas_data too (liquibase names)


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
        "for c in (\"rm a.txt\", \"aws s3 ls\", \"redis-cli GET k\", \"ls -la\"):\n"
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


def _remote(proj: Path, cmd: str):
    r = _evaluate(proj, cmd)
    return (r.prediction or {}).get("remote") or {}, (r.prediction or {}).get("uncovered") or []


def test_3_money_is_a_payment_other_stripe_writes_are_api_writes(tmp_path: Path):
    """Ruling D2 (a): money moved = external_payment (deny); any other write asks."""
    _make_fixture(tmp_path / "p")
    p = tmp_path / "p"
    for cmd in ("stripe refunds create --charge ch_1", "stripe payouts create --amount 1",
                "stripe payment_intents confirm pi_1"):
        assert _remote(p, cmd)[0] == {"payment:stripe": "SEND"}, cmd
    assert _remote(p, "stripe customers update cus_1 --email a@b.c")[0] == {"http:api.stripe.com": "OVERWRITE"}
    assert _remote(p, "stripe customers delete cus_1")[0] == {"http:api.stripe.com": "DELETE"}
    assert _remote(p, "stripe customers list") == ({}, [])


def test_4_offline_and_read_modes_change_nothing(tmp_path: Path):
    """VERIFIED: --sql (alembic) and *Sql (liquibase) only print SQL; status
    commands read. Every such row was ESCALATE on today's path."""
    _make_fixture(tmp_path / "p")
    p = tmp_path / "p"
    for cmd in ("alembic downgrade base --sql", "liquibase update-sql", "liquibase status",
                "rails db:migrate:status", "manage.py migrate --plan", "flyway info"):
        assert _remote(p, cmd) == ({}, []), cmd
    assert _remote(p, "flyway -url=jdbc:x clean migrate")[0] == {"migration:flyway": "DELETE"}   # the worst
    assert _remote(p, "liquibase dropAll")[0] == {"migration:liquibase": "DELETE"}                 # camelCase too
