from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import assert_restores
from demo_cli.config import Config
from demo_cli.engine.rules import RULES
from demo_cli.engine.simulate import Budget, State, World, simulate
from demo_cli.guard import Guard, agent_directory

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))


def _sub_env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC_DIR
    env.pop("BASH_ENV", None)
    env.pop("DEMO_CLI_DISABLE", None)
    env["NO_COLOR"] = "1"
    return env


# ------------------------------------------------------------------------------
# Test 1: A FIFO is not read (Linux / POSIX)
# ------------------------------------------------------------------------------

@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="os.mkfifo not available")
def test_1_a_fifo_is_not_read(tmp_path):
    (tmp_path / "app.db").write_bytes(b"")
    os.mkfifo(tmp_path / "q.sql")

    code = f"""
import json, sys
from demo_cli.engine.simulate import simulate
imp = simulate('sqlite3 app.db ".read q.sql"', cwd={repr(str(tmp_path))}, budget_ms=10_000)
print(json.dumps([why for _u, why in imp.unknown]))
"""
    res = subprocess.run([sys.executable, "-c", code], cwd=str(tmp_path), env=_sub_env(), capture_output=True, text=True, timeout=30)
    assert res.returncode == 0
    reasons = json.loads(res.stdout.strip())
    assert reasons == ["the SQL it runs is unknown: q.sql is not a regular file"]


# ------------------------------------------------------------------------------
# Test 2: A link to a device is not read
# ------------------------------------------------------------------------------

@pytest.mark.skipif(not os.path.exists("/dev/zero") or not hasattr(os, "symlink"), reason="/dev/zero or symlink not available")
def test_2_a_link_to_a_device_is_not_read(tmp_path):
    (tmp_path / "app.db").write_bytes(b"")
    os.symlink("/dev/zero", tmp_path / "q.sql")

    code = f"""
import json, sys
from demo_cli.engine.simulate import simulate
imp = simulate('sqlite3 app.db ".read q.sql"', cwd={repr(str(tmp_path))}, budget_ms=10_000)
print(json.dumps([why for _u, why in imp.unknown]))
"""
    res = subprocess.run([sys.executable, "-c", code], cwd=str(tmp_path), env=_sub_env(), capture_output=True, text=True, timeout=30)
    assert res.returncode == 0
    reasons = json.loads(res.stdout.strip())
    assert reasons == ["the SQL it runs is unknown: q.sql is not a regular file"]


# ------------------------------------------------------------------------------
# Test 3: A regular file reads as before (Control for 1 and 2)
# ------------------------------------------------------------------------------

def test_3_a_regular_file_reads_as_before(tmp_path):
    (tmp_path / "r.sql").write_bytes(b"DELETE FROM t;\r\n")
    app_db = tmp_path / "app.db"
    app_db.write_bytes(b"")

    imp = simulate('sqlite3 app.db ".read r.sql"', cwd=str(tmp_path), budget_ms=10_000)
    assert set(imp.destroys) == {str(app_db)}
    assert imp.unknown == []

    root = str(tmp_path)
    w = World(RULES, Budget(10_000))
    st = State({}, root, root, {})
    text, why = w.read_text(st, os.path.join(root, "r.sql"), 1024)
    assert text == "DELETE FROM t;\n"
    assert why == ""


# ------------------------------------------------------------------------------
# Test 4: The cap is exact (Control)
# ------------------------------------------------------------------------------

def test_4_the_cap_is_exact(tmp_path):
    (tmp_path / "big.sql").write_bytes(b"x" * 1025)
    (tmp_path / "ok.sql").write_bytes(b"x" * 1024)

    root = str(tmp_path)
    w = World(RULES, Budget(10_000))
    st = State({}, root, root, {})
    res_big, why_big = w.read_text(st, os.path.join(root, "big.sql"), 1024)
    assert res_big is None
    assert why_big == "big.sql is larger than 1 KiB"

    res_ok, why_ok = w.read_text(st, os.path.join(root, "ok.sql"), 1024)
    assert res_ok == "x" * 1024
    assert why_ok == ""


# ------------------------------------------------------------------------------
# Test 5: A value that is an option is not understood
# ------------------------------------------------------------------------------

def test_5_a_known_value_that_is_an_option_is_read_as_one(tmp_path):
    # M2.3b: the value is known on the line, so the engine reads it as the
    # option it is (I1a had left it not understood: options were parsed
    # before the value was known).
    (tmp_path / "a.txt").write_bytes(b"a")
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / "m.py").write_bytes(b"m")

    option_cmds = [
        "X=-rf; rm $X src",
        'X="-rf src"; rm $X',
        'X=-rf; rm "$X" src',
    ]
    for cmd in option_cmds:
        imp = simulate(cmd, cwd=str(tmp_path), budget_ms=10_000)
        assert set(imp.destroys) == {str(src)}, cmd
        assert imp.unknown == [], cmd
    imp = simulate("rm $X src", cwd=str(tmp_path), budget_ms=10_000)
    assert (imp.destroys, [why for _u, why in imp.unknown]) == ({}, ["$X is not set on this line"])

    # Controls:
    imp_ctrl1 = simulate("X=src; rm -rf $X", cwd=str(tmp_path), budget_ms=10_000)
    assert set(imp_ctrl1.destroys) == {str(src)}
    assert imp_ctrl1.unknown == []

    imp_ctrl2 = simulate("X=a.txt; rm $X", cwd=str(tmp_path), budget_ms=10_000)
    assert set(imp_ctrl2.destroys) == {str(tmp_path / "a.txt")}
    assert imp_ctrl2.unknown == []


# ------------------------------------------------------------------------------
# Test 6: A glob hit that is an option is not understood
# ------------------------------------------------------------------------------

def test_6_a_glob_hit_that_is_an_option_is_not_understood(tmp_path):
    (tmp_path / "-rf").write_bytes(b"option file")
    (tmp_path / "a.txt").write_bytes(b"a")
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / "m.py").write_bytes(b"m")

    imp = simulate("rm *", cwd=str(tmp_path), budget_ms=10_000)
    assert imp.destroys == {}
    assert [why for _u, why in imp.unknown] == ["a file name that starts with '-' would be read as an option"]

    # Controls:
    imp1 = simulate("rm ./*", cwd=str(tmp_path), budget_ms=10_000)
    assert set(imp1.destroys) == {str(tmp_path / "-rf"), str(tmp_path / "a.txt")}
    assert imp1.unknown == []

    imp2 = simulate("rm *.txt", cwd=str(tmp_path), budget_ms=10_000)
    assert set(imp2.destroys) == {str(tmp_path / "a.txt")}
    assert imp2.unknown == []

    imp3 = simulate("rm src/*", cwd=str(tmp_path), budget_ms=10_000)
    assert set(imp3.destroys) == {str(src / "m.py")}
    assert imp3.unknown == []


# ------------------------------------------------------------------------------
# Test 7: The decision falls back to what reads it right
# ------------------------------------------------------------------------------

def _make_fixture_7(root_path: Path):
    (root_path / ".demo_cli.toml").write_text('mode = "enforce"\n', encoding="utf-8")
    (root_path / "a.txt").write_bytes(b"A")
    (root_path / "list.txt").write_bytes(b"a.txt\n")
    src = root_path / "src"
    src.mkdir(exist_ok=True)
    (src / "m.py").write_bytes(b"x")
    (src / "n.py").write_bytes(b"y")


def test_7_the_decision_falls_back_to_what_reads_it_right(tmp_path, monkeypatch):
    # M2.3b: no runtime net here, so part 2 escalates on every machine.
    from demo_cli import mountstate, syscall_guard
    from demo_cli.mountstate import MountStatus
    monkeypatch.setattr(syscall_guard, "available", lambda: False)
    monkeypatch.setattr(mountstate, "status", lambda cfg: MountStatus(recorded=False, running=False))
    # 1. X=-rf; rm $X src -> REVERSIBLE, both files in src restored
    root1 = tmp_path / "p1"
    root1.mkdir()
    _make_fixture_7(root1)
    cfg1 = Config(project_root=str(root1), mode="enforce")
    g1 = Guard(config=cfg1)
    with agent_directory(str(root1)):
        r1 = g1.evaluate("X=-rf; rm $X src", door="agent", can_supervise=True)
    assert r1.decision.decision == "REVERSIBLE"
    assert r1.recovery_entry is not None
    assert_restores(r1.recovery_entry, str(root1), {"src/m.py": b"x", "src/n.py": b"y"})

    # 2. touch -- -rf; rm * -> ESCALATE, no recovery entry
    root2 = tmp_path / "p2"
    root2.mkdir()
    _make_fixture_7(root2)
    cfg2 = Config(project_root=str(root2), mode="enforce")
    g2 = Guard(config=cfg2)
    with agent_directory(str(root2)):
        r2 = g2.evaluate("touch -- -rf; rm *", door="agent", can_supervise=True)
    assert r2.decision.decision == "ESCALATE"
    assert r2.recovery_entry is None

    # 3. Control in fresh copy of fixture: rm ./* -> REVERSIBLE
    root3 = tmp_path / "p3"
    root3.mkdir()
    _make_fixture_7(root3)
    cfg3 = Config(project_root=str(root3), mode="enforce")
    g3 = Guard(config=cfg3)
    with agent_directory(str(root3)):
        r3 = g3.evaluate("rm ./*", door="agent", can_supervise=True)
    assert r3.decision.decision == "REVERSIBLE"
    assert r3.recovery_entry is not None
    assert_restores(r3.recovery_entry, str(root3), {"a.txt": b"A", "list.txt": b"a.txt\n"})


# ------------------------------------------------------------------------------
# Test 8: /dev/null reads as empty
# ------------------------------------------------------------------------------

@pytest.mark.skipif(not os.path.exists("/dev/null"), reason="/dev/null not available")
def test_8_dev_null_reads_empty(tmp_path):
    root = str(tmp_path)
    w = World(RULES, Budget(10_000))
    st = State({}, root, root, {})
    text, why = w.read_text(st, "/dev/null", 1024)
    assert text == ""
    assert why == ""

    imp = simulate("sqlite3 new.db < /dev/null", cwd=root, budget_ms=10_000)
    assert imp.creates == set()
    assert imp.unknown == []
