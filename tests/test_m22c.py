"""M2.2c: what a system command changes on this machine - services, power,
processes, accounts, disks, the machine's own recovery data, network and
firewall, file modes and owners, the Windows registry - as engine rules
(rulings C1-C10, Nizar, 2026-10-07).

Rows and expected results in tests/fixtures/m22c/, measured by ORCH on the
prototype on Linux and Windows Python 3.14 (identical).
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

from demo_cli import policy, recovery
from demo_cli.config import Config
from demo_cli.guard import Guard, agent_directory

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "m22c"
MODULES = ("system_ops", "system_data", "rules_system")
CONTROL = "systemctl stop nginx"     # loads system_data too (systemctl's verbs)


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
    assert len(rows) == len(expected) == 187
    for idx, row in enumerate(rows):
        cmd = row["cmd"]
        exp = expected[cmd]
        proj = tmp_path / f"p_{idx}"
        _make_fixture(proj)
        r = _evaluate(proj, cmd)
        assert ((r.prediction or {}).get("uncovered") or []) == exp["uncovered"], cmd
        assert ((r.prediction or {}).get("remote") or {}) == exp["remote"], cmd
        assert (r.recovery_entry is not None) == exp["captured"], cmd
        assert r.decision.decision == exp["decision"], cmd
        assert r.classification.nonrecoverable_surface == exp["surface"], cmd


def test_2_loaded_only_when_named(tmp_path: Path):
    code = (
        "import os, sys\n"
        "from demo_cli.config import Config\n"
        "from demo_cli.engine import predict\n"
        "cfg = Config(project_root=os.getcwd())\n"
        "for c in (\"rm a.txt\", \"aws s3 ls\", \"redis-cli GET k\", \"ls -la\", \"ps aux\"):\n"
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


def _decision(proj: Path, cmd: str):
    r = _evaluate(proj, cmd)
    return (r.decision.decision, r.classification.nonrecoverable_surface,
            r.decision.approvable, (r.prediction or {}).get("remote") or {})


def test_3_each_ruling_reaches_its_surface_and_channel(tmp_path: Path):
    p = tmp_path / "p"
    _make_fixture(p)
    # (command, surface, a person may approve it on the spot)
    cases = [
        ("systemctl stop nginx", "service_control", True),                 # C1
        ("reboot", "host_power", True),                                     # C2
        ("kill $(lsof -ti:3000)", "process_control", True),                 # C3: lsof only reads
        ("sudo useradd -m eve", "account_control", False),                  # C4: additions too
        ("wipefs -a /dev/sdb", "disk_format", False),                       # C5
        ("vssadmin delete shadows /all /quiet", "system_recovery", False),  # C6
        ("iptables -F", "host_network", True),                              # C7
        ("chown -R nobody sub", "file_ownership", True),                    # C8
        ("reg delete 'HKCU\\Software\\X' //f", "system_config", True),      # C9
    ]
    for cmd, surface, ask in cases:
        d, s, approvable, _ = _decision(p, cmd)
        assert (d, s, approvable) == ("ESCALATE", surface, ask), cmd
        assert policy.may_ask(s) is ask, cmd


def test_4_reads_and_keeps_change_nothing_they_should_not(tmp_path: Path):
    p = tmp_path / "p"
    _make_fixture(p)
    for cmd in ("kill -l", "kill -0 1234", "killall -l", "systemctl status nginx",
                "systemctl --dry-run reboot", "shutdown -c", "shutdown /a", "wipefs /dev/sdb",
                "fdisk -l", "ufw --dry-run reset", "iptables -nvL", "ip a", "nmcli device status",
                "net user", "sc query", "bcdedit /enum", "passwd -S bob", "ps aux"):
        assert _decision(p, cmd) == ("ALLOW", None, False, {}), cmd
    # C1: a restart is allowed AND named in the reason (listed, not silent)
    r = _evaluate(p, "systemctl restart nginx")
    assert r.decision.decision == "ALLOW"
    assert (r.prediction or {}).get("remote") == {"service:systemd@local": "SERVICE_KEEP"}
    assert "Recorded and allowed: service:systemd@local" in r.decision.reason
    # systemctl(1): --dry-run is honoured by the power verbs only
    assert _decision(p, "systemctl --dry-run stop nginx")[0] == "ESCALATE"
    # C10: what schedules code is M2.2d's - uncovered here
    assert (_evaluate(p, "systemctl enable nginx").prediction or {}).get("uncovered") == [
        "systemctl enable"]


def test_5_chmod_is_captured_in_the_project_and_escalates_outside(tmp_path: Path):
    """Ruling C8. A directory snapshot restores every mode (VERIFIED
    2026-10-07): the change is undone byte- and mode-exact."""
    p = tmp_path / "p"
    _make_fixture(p)
    before = {q: stat.S_IMODE(os.stat(p / q).st_mode) for q in ("a.txt", "sub", "sub/s.txt")}
    r = _evaluate(p, "chmod -R 444 sub && chmod 444 a.txt")
    assert r.decision.decision == "REVERSIBLE"
    assert r.recovery_entry is not None
    os.chmod(p / "sub" / "s.txt", 0o444)
    os.chmod(p / "a.txt", 0o444)
    assert recovery.restore(r.recovery_entry).ok
    after = {q: stat.S_IMODE(os.stat(p / q).st_mode) for q in ("a.txt", "sub", "sub/s.txt")}
    assert after == before
    assert (p / "a.txt").read_bytes() == b"A"
    # a directory left with no permission at all: undo still restores it
    r = _evaluate(p, "chmod -R 000 sub")
    assert r.decision.decision == "REVERSIBLE"
    os.chmod(p / "sub" / "s.txt", 0)
    os.chmod(p / "sub", 0)
    assert recovery.restore(r.recovery_entry).ok
    assert {q: stat.S_IMODE(os.stat(p / q).st_mode) for q in ("sub", "sub/s.txt")} == {
        q: before[q] for q in ("sub", "sub/s.txt")}
    assert (p / "sub" / "s.txt").read_bytes() == b"s"
    # outside the project: nothing can capture it, so it escalates (and a person may approve)
    outside = tmp_path / "elsewhere.txt"
    outside.write_bytes(b"o")
    r = _evaluate(p, f"chmod 600 '{outside.as_posix()}'")
    assert (r.decision.decision, r.classification.nonrecoverable_surface,
            r.decision.approvable, r.recovery_entry) == ("ESCALATE", None, True, None)


def test_6_grammars_read_as_the_tools_read_them(tmp_path: Path):
    p = tmp_path / "p"
    _make_fixture(p)
    remote = lambda cmd: _decision(p, cmd)[3]                       # noqa: E731
    # iproute2 prefixes (VERIFIED in an empty network namespace)
    assert remote("ip l s eth0 down") == {"net:link@local": "SERVICE_LOSS"}
    assert remote("ip a f dev eth0") == {"net:link@local": "DELETE"}
    assert remote("ip a") == {}
    # getopt_long: a unique prefix of a long option is that option
    assert remote("iptables --fl") == {"net:firewall@local": "DELETE"}
    assert remote("systemctl --no-p stop nginx") == {"service:systemd@local": "SERVICE_LOSS"}
    # chmod: -x is a mode, not an option
    assert _decision(p, "chmod -x a.txt")[0] == "REVERSIBLE"
    # Windows switches from Git Bash: /x, //x and -x read alike
    for spelling in ("/f", "//f", "-f"):
        assert remote(f"taskkill {spelling} /im node.exe") == {"process:local": "SERVICE_LOSS"}
    # kill: PID 1 or -1 is every process
    assert remote("kill -9 -1") == {"power:local": "SERVICE_LOSS"}
    assert remote("kill -9 1234") == {"process:local": "SERVICE_LOSS"}


def test_7_odd_arguments_never_break_the_engine(tmp_path: Path):
    from demo_cli.engine import predict
    from demo_cli.engine.system_ops import TOOLS
    (tmp_path / "a.txt").write_text("a")
    cfg = Config(project_root=str(tmp_path))
    tails = ("", "--", "-", "$X", "/?", "//?", "-h", "x y", "--weird=1", "a.txt", "-1",
             "delete", "set lo down", "\\\\\\\\HOST delete")
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        for tool in TOOLS:
            for tail in tails:
                predict(f"{tool} {tail}".strip(), cfg, budget_ms=10000)
    finally:
        os.chdir(cwd)
