from __future__ import annotations

import io
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import assert_restores
from demo_cli import guard, recovery, syscall_guard
from demo_cli.classify import Classification
from demo_cli.config import Config
from demo_cli.context import Context, build_context
from demo_cli.decide import Decision
from demo_cli.engine.rules import RULES
from demo_cli.engine.simulate import simulate
from demo_cli.guard import Guard, GuardResult
from demo_cli.hooks.claude_code import run_pretooluse


SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))


def _sub_env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC_DIR
    # Hermetic: clear BASH_ENV so inner bash does not re-fire shell guard (see test_syscall_guard.py:22-25)
    env.pop("BASH_ENV", None)
    env.pop("DEMO_CLI_DISABLE", None)
    env["NO_COLOR"] = "1"
    return env


# ------------------------------------------------------------------------------
# Test 1: The hook, enforce, SUPERVISED
# ------------------------------------------------------------------------------

@pytest.mark.skipif(not syscall_guard.available(), reason="Linux x86-64 syscall guard required")
def test_1_hook_enforce_supervised(tmp_path):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n', encoding="utf-8")
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "rm $(git ls-files -o)",
            "description": "clean untracked files",
        },
        "cwd": str(tmp_path),
    }
    out = io.StringIO()
    rc = run_pretooluse(io.StringIO(json.dumps(payload)), out)
    assert rc == 0
    resp_top = json.loads(out.getvalue())
    resp = resp_top["hookSpecificOutput"]

    assert "permissionDecision" not in resp
    assert resp["updatedInput"]["command"].startswith(guard._launcher() + " sh -g ")
    assert resp["updatedInput"].get("description") == "clean untracked files"
    assert "systemMessage" in resp_top
    assert "rm $(git ls-files -o)" in resp_top["systemMessage"]
    assert "additionalContext" in resp
    assert "undo with" in resp["additionalContext"]


# ------------------------------------------------------------------------------
# Test 2: The same in shadow mode
# ------------------------------------------------------------------------------

@pytest.mark.skipif(not syscall_guard.available(), reason="Linux x86-64 syscall guard required")
def test_2_hook_shadow_supervised(tmp_path):
    (tmp_path / ".demo_cli.toml").write_text('mode = "shadow"\n', encoding="utf-8")
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "rm $(git ls-files -o)",
            "description": "clean untracked files",
        },
        "cwd": str(tmp_path),
    }
    out = io.StringIO()
    rc = run_pretooluse(io.StringIO(json.dumps(payload)), out)
    assert rc == 0
    resp_top = json.loads(out.getvalue())
    resp = resp_top["hookSpecificOutput"]

    assert "permissionDecision" not in resp
    assert resp["updatedInput"]["command"].startswith(guard._launcher() + " sh -g ")
    assert resp["updatedInput"].get("description") == "clean untracked files"
    assert "systemMessage" in resp_top
    assert "rm $(git ls-files -o)" in resp_top["systemMessage"]
    assert "additionalContext" in resp
    assert "undo with" in resp["additionalContext"]


# ------------------------------------------------------------------------------
# Test 3: The 200-character cap
# ------------------------------------------------------------------------------

@pytest.mark.skipif(not syscall_guard.available(), reason="Linux x86-64 syscall guard required")
def test_3_hook_supervised_200_character_cap(tmp_path):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n', encoding="utf-8")
    long_arg = "x" * 500
    long_cmd = f"rm $(git ls-files -o) {long_arg}"
    assert len(long_cmd) > 200
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": long_cmd,
            "description": "long command test",
        },
        "cwd": str(tmp_path),
    }
    out = io.StringIO()
    rc = run_pretooluse(io.StringIO(json.dumps(payload)), out)
    assert rc == 0
    resp_top = json.loads(out.getvalue())
    resp = resp_top["hookSpecificOutput"]

    sys_msg = resp_top.get("systemMessage", "")
    add_ctx = resp.get("additionalContext", "")
    rewrite = resp["updatedInput"]["command"]

    expected_truncated = long_cmd[:200] + "…"
    assert expected_truncated in sys_msg
    assert long_cmd not in sys_msg
    assert rewrite in add_ctx


# ------------------------------------------------------------------------------
# Test 4: demo_cli sh really supervises (Linux)
# ------------------------------------------------------------------------------

@pytest.mark.skipif(not syscall_guard.available(), reason="Linux x86-64 syscall guard required")
def test_4_demo_cli_sh_really_supervises(tmp_path):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n', encoding="utf-8")
    a_txt = tmp_path / "a.txt"
    a_txt.write_bytes(b"byte-exact content for t1")

    launcher = guard._launcher()
    cmd = shlex.split(launcher) + ["sh", "-g", "t1", "rm a.txt"]
    res = subprocess.run(cmd, cwd=str(tmp_path), env=_sub_env(), capture_output=True, text=True)
    assert res.returncode == 0, f"stdout: {res.stdout}, stderr: {res.stderr}"

    assert not a_txt.exists()
    rec_dir = os.path.join(str(tmp_path), ".demo_cli", "recovery")
    entries = recovery.find_group(rec_dir, "t1")
    assert len(entries) == 1, "recovery.find_group did not return exactly 1 entry"
    assert_restores(entries[0], str(tmp_path), {"a.txt": b"byte-exact content for t1"})
    assert a_txt.read_bytes() == b"byte-exact content for t1"


# ------------------------------------------------------------------------------
# Test 5: Already traced -> direct exec (Linux)
# ------------------------------------------------------------------------------

@pytest.mark.skipif(not syscall_guard.available(), reason="Linux x86-64 syscall guard required")
def test_5_already_traced_direct_exec(tmp_path):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n', encoding="utf-8")
    a_txt = tmp_path / "a.txt"
    a_txt.write_bytes(b"content for nested trace test")

    launcher = guard._launcher()
    nested_cmd = f"{launcher} sh -g t3 'rm a.txt'"
    cmd = shlex.split(launcher) + ["sh", "-g", "t2", nested_cmd]
    res = subprocess.run(cmd, cwd=str(tmp_path), env=_sub_env(), capture_output=True, text=True)
    assert res.returncode == 0, f"stdout: {res.stdout}, stderr: {res.stderr}"
    assert not a_txt.exists()
    assert "cannot trace" not in res.stderr

    rec_dir = os.path.join(str(tmp_path), ".demo_cli", "recovery")
    entries_t2 = recovery.find_group(rec_dir, "t2")
    assert len(entries_t2) == 1, f"expected 1 snapshot in t2, got {len(entries_t2)}"
    entries_t3 = recovery.find_group(rec_dir, "t3")
    assert len(entries_t3) == 0, f"expected 0 snapshots in t3 (direct exec), got {len(entries_t3)}"
    assert_restores(entries_t2[0], str(tmp_path), {"a.txt": b"content for nested trace test"})


# ------------------------------------------------------------------------------
# Test 6: The wrapper is unwrapped, judged on what it hides
# ------------------------------------------------------------------------------

def test_6_wrapper_unwrapped_judged_on_what_it_hides(tmp_path):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n', encoding="utf-8")
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)

    # 1. demo_cli sh 'terraform destroy' -> ESCALATE, surface infra_destroy
    r1 = g.evaluate("demo_cli sh 'terraform destroy'")
    assert r1.decision.decision == "ESCALATE"
    assert r1.classification.nonrecoverable_surface == "infra_destroy"

    # 2. python3 -m demo_cli run -- bash -c 'rm a.txt' -> REVERSIBLE, a.txt captured
    a_txt = tmp_path / "a.txt"
    a_txt.write_bytes(b"hello a")
    r2 = g.evaluate("python3 -m demo_cli run -- bash -c 'rm a.txt'")
    assert r2.decision.decision == "REVERSIBLE"
    assert r2.recovery_entry is not None
    assert_restores(r2.recovery_entry, str(tmp_path), {"a.txt": b"hello a"})

    # 3. /usr/local/bin/demo_cli sh -g x 'rm a.txt' -> REVERSIBLE
    r3 = g.evaluate("/usr/local/bin/demo_cli sh -g x 'rm a.txt'")
    assert r3.decision.decision == "REVERSIBLE"

    # 4. control: demo_cli status -> ALLOW, nothing captured
    r4 = g.evaluate("demo_cli status")
    assert r4.decision.decision == "ALLOW"
    assert r4.recovery_entry is None


# ------------------------------------------------------------------------------
# Test 7: The engine sees through it
# ------------------------------------------------------------------------------

def test_7_engine_sees_through_wrapper(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"target")
    impact_bash = simulate("bash -c 'rm a.txt'", cwd=str(tmp_path))
    impact_sh = simulate("demo_cli sh 'rm a.txt'", cwd=str(tmp_path))
    assert impact_sh.destroys == impact_bash.destroys
    assert any(p.endswith("a.txt") for p in impact_sh.destroys)


# ------------------------------------------------------------------------------
# Test 8: Pure-function tracer identification (Fix 1)
# ------------------------------------------------------------------------------

def test_8_tracer_is_ours_pure():
    status_traced = "Name:\tsh\nState:\tS (sleeping)\nTracerPid:\t12345\nUid:\t1000\t1000\t1000\t1000\n"
    status_not_traced = "Name:\tsh\nState:\tS (sleeping)\nTracerPid:\t0\nUid:\t1000\t1000\t1000\t1000\n"

    # 1. ours via Shape 1: /usr/local/bin/demo_cli sh -g x ...
    cmd_demo_sh = b"/usr/local/bin/demo_cli\x00sh\x00-g\x00x\x00rm a.txt\x00"
    assert syscall_guard._tracer_is_ours(status_traced, cmd_demo_sh) is True

    # 2. ours via Shape 3: python3 -m demo_cli run --group x -- ...
    cmd_py_run = b"python3\x00-m\x00demo_cli\x00run\x00--group\x00x\x00--\x00rm a.txt\x00"
    assert syscall_guard._tracer_is_ours(status_traced, cmd_py_run) is True

    # 3. ours via Shape 2: /usr/bin/python3.13 /home/u/.local/bin/demo_cli sh -g ab12 cmd
    cmd_py_script = b"/usr/bin/python3.13\x00/home/u/.local/bin/demo_cli\x00sh\x00-g\x00ab12\x00cmd\x00"
    assert syscall_guard._tracer_is_ours(status_traced, cmd_py_script) is True

    # 4. ours via Shape 2: Windows python.exe Scripts\demo_cli.exe sh -g x cmd
    cmd_win_script = b"C:\\Python\\python.exe\x00C:\\Python\\Scripts\\demo_cli.exe\x00sh\x00-g\x00x\x00cmd\x00"
    assert syscall_guard._tracer_is_ours(status_traced, cmd_win_script) is True

    # 5. NOT ours: foreign python tracer script with demo_cli in args
    cmd_wrong_1 = b"python3\x00/tmp/my_tracer.py\x00/home/u/.local/bin/demo_cli\x00sh\x00-g\x00t\x00rm a.txt\x00"
    assert syscall_guard._tracer_is_ours(status_traced, cmd_wrong_1) is False

    # 6. NOT ours: python -c with sh and demo_cli in args
    cmd_wrong_2 = b"python3\x00-c\x00import ptrace\x00sh\x00demo_cli\x00"
    assert syscall_guard._tracer_is_ours(status_traced, cmd_wrong_2) is False

    # 7. NOT ours: python3 -I -m demo_cli sh x (extra flags before -m)
    cmd_wrong_flags = b"python3\x00-I\x00-m\x00demo_cli\x00sh\x00x\x00"
    assert syscall_guard._tracer_is_ours(status_traced, cmd_wrong_flags) is False

    # 8. NOT ours via strace -f ...
    cmd_strace = b"strace\x00-f\x00-o\x00/dev/null\x00/usr/local/bin/demo_cli\x00sh\x00-g\x00t9\x00rm a.txt\x00"
    assert syscall_guard._tracer_is_ours(status_traced, cmd_strace) is False

    # 9. NOT ours via gdb ...
    cmd_gdb = b"gdb\x00--args\x00/usr/local/bin/demo_cli\x00sh\x00-g\x00t9\x00rm a.txt\x00"
    assert syscall_guard._tracer_is_ours(status_traced, cmd_gdb) is False

    # 10. Control: TracerPid == 0 is never ours
    assert syscall_guard._tracer_is_ours(status_not_traced, cmd_demo_sh) is False


# ------------------------------------------------------------------------------
# Test 9: Foreign tracer refused under strace (Fix 1 e2e)
# ------------------------------------------------------------------------------

@pytest.mark.skipif(shutil.which("strace") is None, reason="strace not installed")
def test_9_foreign_tracer_refused_strace(tmp_path):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n', encoding="utf-8")
    a_txt = tmp_path / "a.txt"
    a_txt.write_bytes(b"survives strace")

    launcher = guard._launcher(tmp_path)
    cmd = ["strace", "-f", "-o", "/dev/null"] + shlex.split(launcher) + ["sh", "-g", "t9", "rm a.txt"]
    res = subprocess.run(cmd, cwd=str(tmp_path), env=_sub_env(), capture_output=True, text=True)
    assert res.returncode == 126
    assert a_txt.exists()
    assert a_txt.read_bytes() == b"survives strace"
    assert "already traced by another process" in res.stderr
    assert "refusing to run unsupervised" in res.stderr


# ------------------------------------------------------------------------------
# Test 10: Windows SUPERVISED without rewrite notice shape (Fix 2)
# ------------------------------------------------------------------------------

def test_10_windows_supervised_without_rewrite_notice(tmp_path, monkeypatch):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n', encoding="utf-8")
    fake_res = GuardResult(
        command="rm file.txt",
        classification=Classification(is_destructive=True),
        context=build_context("rm file.txt", cwd=str(tmp_path)),
        decision=Decision(decision="SUPERVISED", reason="covered by the demo_cli filesystem mount: WinFsp driver active"),
        mode="enforce",
        rewrite=None,
    )
    monkeypatch.setattr(Guard, "evaluate", lambda *args, **kwargs: fake_res)

    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "rm file.txt",
            "description": "test windows mount supervised notice",
        },
        "cwd": str(tmp_path),
    }
    out = io.StringIO()
    rc = run_pretooluse(io.StringIO(json.dumps(payload)), out)
    assert rc == 0
    resp_top = json.loads(out.getvalue())
    resp = resp_top["hookSpecificOutput"]

    assert "permissionDecision" not in resp
    assert "filesystem mount" in resp.get("additionalContext", "")
    assert "filesystem mount" in resp_top.get("systemMessage", "")


# ------------------------------------------------------------------------------
# Test 11: Launcher fallback when inside project (Fix 3)
# ------------------------------------------------------------------------------

def test_11_launcher_fallback_when_inside_project(tmp_path, monkeypatch):
    inside_cand = tmp_path / "venv" / "bin" / "demo_cli"
    inside_cand.parent.mkdir(parents=True, exist_ok=True)
    inside_cand.write_text("#!/bin/sh\n", encoding="utf-8")

    monkeypatch.setattr(shutil, "which", lambda cmd: str(inside_cand))
    guard._launcher.cache_clear()
    try:
        launcher = guard._launcher(project_root=tmp_path)
        assert launcher == f"{sys.executable} -m demo_cli"

        guard._launcher.cache_clear()
        launcher_str = guard._launcher(project_root=str(tmp_path))
        assert launcher_str == f"{sys.executable} -m demo_cli"

        # Control: launcher outside project returns candidate path
        outside_cand = "/usr/local/bin/demo_cli" if os.name != "nt" else r"C:\demo_cli\demo_cli.exe"
        monkeypatch.setattr(shutil, "which", lambda cmd: outside_cand)
        guard._launcher.cache_clear()
        launcher_out = guard._launcher(project_root=tmp_path)
        assert launcher_out == os.path.abspath(outside_cand)
    finally:
        guard._launcher.cache_clear()


# ------------------------------------------------------------------------------
# Test 12: Foreign python tracer refused (Linux end-to-end without strace)
# ------------------------------------------------------------------------------

@pytest.mark.skipif(not syscall_guard.available(), reason="Linux x86-64 syscall guard required")
def test_12_foreign_python_tracer_refused(tmp_path):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n', encoding="utf-8")
    a_txt = tmp_path / "a.txt"
    a_txt.write_bytes(b"survives foreign python tracer")

    tracer_py = tmp_path / "tracer.py"
    tracer_py.write_text('''import ctypes, os, sys
libc = ctypes.CDLL("libc.so.6")
PTRACE_TRACEME = 0
PTRACE_CONT = 7

cmd = sys.argv[1:]
pid = os.fork()
if pid == 0:
    libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
    os.execv(cmd[0], cmd)

while True:
    wpid, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status):
        sys.exit(os.WEXITSTATUS(status))
    if os.WIFSIGNALED(status):
        sys.exit(128 + os.WTERMSIG(status))
    libc.ptrace(PTRACE_CONT, pid, 0, 0)
''', encoding="utf-8")

    launcher = guard._launcher(tmp_path)
    launcher_cmd = shlex.split(launcher) + ["sh", "-g", "t12", "rm a.txt"]
    cmd = [sys.executable, str(tracer_py)] + launcher_cmd
    res = subprocess.run(cmd, cwd=str(tmp_path), env=_sub_env(), capture_output=True, text=True)
    assert res.returncode == 126
    assert a_txt.exists()
    assert a_txt.read_bytes() == b"survives foreign python tracer"
    assert "already traced by another process" in res.stderr
    assert "refusing to run unsupervised" in res.stderr


