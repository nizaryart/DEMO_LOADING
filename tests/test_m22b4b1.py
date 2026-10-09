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

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "m22b4b1"
MODULES = ("paas_ops", "paas_data", "rules_paas")
CONTROL = "heroku apps:info -a x"


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


def test_3_what_runs_locally_or_as_a_preview_is_not_the_platform(tmp_path: Path):
    """VERIFIED: wrangler kv / d1 data act locally unless --remote; a vercel or
    netlify deploy without production is a preview / draft (a creation)."""
    _make_fixture(tmp_path / "p")
    p = tmp_path / "p"
    # M2.3b: a write to wrangler's local state is NOT UNDERSTOOD now (it was
    # left to the old path as uncovered); test_m23b pins the decision.
    assert _remote(p, "wrangler kv key delete K") == ({}, [])
    assert _remote(p, "wrangler kv key delete K --remote")[0] == {"deploy:wrangler": "DELETE"}
    assert _remote(p, 'wrangler d1 execute db --command "DROP TABLE t"') == ({}, [])
    assert _remote(p, "vercel deploy") == ({}, ["vercel deploy (a preview)"])
    assert _remote(p, "vercel deploy --target production")[0] == {"deploy:vercel": "OVERWRITE"}
    assert _remote(p, "netlify deploy --prod --draft") == ({}, ["netlify deploy (a draft)"])


def test_4_names_are_read_as_each_tool_reads_them(tmp_path: Path):
    _make_fixture(tmp_path / "p")
    p = tmp_path / "p"
    assert _remote(p, "firebase FIRESTORE:DELETE /users")[0] == {"deploy:firebase": "DELETE"}   # case-insensitive
    assert _remote(p, "fly m rm 123")[0] == {"paas:fly": "DELETE"}                             # alias of an alias
    assert _remote(p, "fly destroy x")[0] == {"paas:fly": "DELETE"}                            # hidden command
    assert _remote(p, "netlify env:delete KEY")[0] == {"deploy:netlify": "OVERWRITE"}          # alias of env:unset
    assert _remote(p, "heroku myplugin:do-thing") == ({}, ["heroku myplugin:do-thing"])        # not heroku's own
