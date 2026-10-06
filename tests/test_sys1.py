"""Part SYS1: behavioral syscall guard connection, Windows mount supervision,
and in-place/background process handling.
"""
import io
import json
import os
import shlex
import signal
import sys
import time
from typing import Optional

import pytest

from demo_cli.classify import Classification, POSIX, POWERSHELL
from demo_cli.config import Config
from demo_cli.decide import (
    ALLOW, CONTEXT_MISMATCH, ESCALATE, REVERSIBLE, SAFE, SUPERVISED,
    decide, posture
)
from demo_cli.guard import Guard, GuardResult
from demo_cli.hooks.claude_code import run_pretooluse
from demo_cli.mountstate import MountStatus
from demo_cli import guard, recovery, syscall_guard


# ==============================================================================
# 1. decide() disposition and posture tests
# ==============================================================================

def test_decide_returns_supervised_when_supervisable_is_true():
    c = Classification(is_destructive=True, is_mutating=True, matched_rule="rm_unresolvable")
    d = decide(c, "production", recovery_captured=False, supervisable=True)
    assert d.decision == SUPERVISED
    assert d.recoverable is True
    assert posture(d.decision) == SAFE
    assert "covered by the syscall guard" in d.reason


def test_decide_names_net_in_reason():
    c = Classification(is_destructive=True, is_mutating=True, matched_rule="rm_unresolvable")
    d_sys = decide(c, "production", recovery_captured=False, supervisable=True, net="syscall_guard")
    assert "covered by the syscall guard" in d_sys.reason

    d_mount = decide(c, "production", recovery_captured=False, supervisable=True, net="mount")
    assert "covered by the demo_cli filesystem mount" in d_mount.reason


def test_decide_supervisable_controls():
    # 1. Remote exec never supervised -> ESCALATE
    c_rx = Classification(is_destructive=True, is_mutating=True, remote_exec=True)
    assert decide(c_rx, "production", recovery_captured=False, supervisable=True).decision == ESCALATE

    # 2. Nonrecoverable surface never supervised -> ESCALATE
    c_surf = Classification(is_destructive=True, is_mutating=True, nonrecoverable_surface="s3")
    assert decide(c_surf, "production", recovery_captured=False, supervisable=True).decision == ESCALATE

    # 3. Context mismatch without capture -> ESCALATE
    c_mut = Classification(is_destructive=True, is_mutating=True)
    mismatches = [("env", "staging", "production")]
    assert decide(c_mut, "production", recovery_captured=False, mismatches=mismatches, supervisable=True).decision == ESCALATE

    # 4. Captured snapshot takes precedence -> REVERSIBLE
    assert decide(c_mut, "production", recovery_captured=True, supervisable=True).decision == REVERSIBLE

    # 5. Non-mutating -> ALLOW
    c_safe = Classification(is_destructive=False, is_mutating=False)
    assert decide(c_safe, "production", recovery_captured=False, supervisable=True).decision == ALLOW


# ==============================================================================
# 2. Guard.evaluate() supervision tests (Linux & Windows)
# ==============================================================================

def test_guard_evaluates_supervised_with_rewrite_on_unresolvable_command(tmp_path):
    if not syscall_guard.available():
        pytest.skip("Linux x86-64 syscall guard not available")
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)
    r = g.evaluate("rm $(cat list.txt)", can_supervise=True)
    assert r.decision.decision == SUPERVISED
    assert r.decision.recoverable is True
    assert r.rewrite is not None
    # B1b (msg 043): the rewrite is now "<launcher> sh -g <id> <quoted cmd>" and carries no permissionDecision.
    assert r.rewrite.startswith(guard._launcher() + " sh -g ")
    assert r.rewrite.endswith(" " + shlex.quote("rm $(cat list.txt)"))
    assert "covered by the syscall guard" in r.decision.reason


def test_guard_skips_supervision_when_can_supervise_false(tmp_path):
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)
    r = g.evaluate("rm $(cat list.txt)", can_supervise=False)
    assert r.decision.decision == ESCALATE
    assert r.rewrite is None


@pytest.mark.skipif(sys.platform != "linux", reason="Linux only")
def test_guard_never_supervises_powershell_on_linux(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "name", "posix")
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)
    r = g.evaluate("Remove-Item $x", dialect=POWERSHELL, can_supervise=True)
    assert r.decision.decision == ESCALATE
    assert r.rewrite is None


def test_guard_skips_checkpoint_when_supervisable(tmp_path):
    if not syscall_guard.available():
        pytest.skip("Linux x86-64 syscall guard not available")
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    cfg.checkpoint = {"enabled": True}
    g = Guard(config=cfg)
    r = g.evaluate("rm $(cat list.txt)", can_supervise=True)
    assert r.decision.decision == SUPERVISED
    assert r.recovery_entry is None  # Checkpoint was skipped


def test_guard_c2_sql_and_git_exclusions(tmp_path):
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)

    # SQL exclusions (server process, local tracer cannot supervise)
    assert g.evaluate('psql -c "DROP TABLE t"', can_supervise=True).decision.decision == ESCALATE
    assert g.evaluate('mysql -e "DROP DATABASE d"', can_supervise=True).decision.decision == ESCALATE

    # git exclusions (modifies .git which is deliberately ignored by both nets)
    assert g.evaluate("git branch -D feat", can_supervise=True).decision.decision == ESCALATE
    assert g.evaluate("git reset --hard HEAD~1", can_supervise=True).decision.decision == ESCALATE

    # Control: unresolvable file delete IS supervised
    if syscall_guard.available():
        assert g.evaluate("rm $(cat list.txt)", can_supervise=True).decision.decision == SUPERVISED


def test_windows_mount_supervisable_mocked(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "name", "nt")
    from demo_cli import mountstate
    monkeypatch.setattr(mountstate, "status", lambda cfg: MountStatus(
        recorded=True, running=True, mountpoint=str(tmp_path)
    ))

    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)

    # On Windows under active mount, unresolvable commands become SUPERVISED without rewrite
    r = g.evaluate("rm $(cat list.txt)")
    assert r.decision.decision == SUPERVISED
    assert r.rewrite is None
    assert "covered by the demo_cli filesystem mount" in r.decision.reason

    # On Windows under active mount, PowerShell commands ARE supervised
    r_ps = g.evaluate("Remove-Item $x", dialect=POWERSHELL)
    assert r_ps.decision.decision == SUPERVISED
    assert r_ps.rewrite is None
    assert "covered by the demo_cli filesystem mount" in r_ps.decision.reason


def test_windows_mount_controls(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "name", "nt")
    from demo_cli import mountstate

    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)

    # 1. Mount status running is None (cannot determine) -> ESCALATE
    monkeypatch.setattr(mountstate, "status", lambda cfg: MountStatus(
        recorded=True, running=None, mountpoint=str(tmp_path)
    ))
    assert g.evaluate("rm $(cat list.txt)").decision.decision == ESCALATE

    # 2. Mount status stale (running False) -> ESCALATE
    monkeypatch.setattr(mountstate, "status", lambda cfg: MountStatus(
        recorded=True, running=False, mountpoint=str(tmp_path)
    ))
    assert g.evaluate("rm $(cat list.txt)").decision.decision == ESCALATE

    # 3. Mountpoint is for another folder -> ESCALATE
    monkeypatch.setattr(mountstate, "status", lambda cfg: MountStatus(
        recorded=True, running=True, mountpoint=str(tmp_path / "other")
    ))
    assert g.evaluate("rm $(cat list.txt)").decision.decision == ESCALATE


# ==============================================================================
# 3. Claude Code PreToolUse hook supervision & rewrite tests
# ==============================================================================

def test_claude_hook_emits_updated_input_on_supervised_bash(tmp_path):
    if not syscall_guard.available():
        pytest.skip("Linux x86-64 syscall guard not available")
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm $(cat list.txt)", "description": "cleanup"},
        "cwd": str(tmp_path),
    }
    out = io.StringIO()
    rc = run_pretooluse(io.StringIO(json.dumps(payload)), out)
    assert rc == 0
    # B1b (msg 043): the rewrite is now "<launcher> sh -g <id> <quoted cmd>" and carries no permissionDecision.
    resp_top = json.loads(out.getvalue())
    resp = resp_top["hookSpecificOutput"]
    assert "permissionDecision" not in resp
    assert "updatedInput" in resp
    assert resp["updatedInput"]["command"].startswith(guard._launcher() + " sh -g ")
    assert resp["updatedInput"]["command"].endswith(" " + shlex.quote("rm $(cat list.txt)"))
    assert "additionalContext" in resp
    assert "systemMessage" in resp_top
    assert "rm $(cat list.txt)" in resp_top["systemMessage"]


def test_claude_hook_never_rewrites_powershell(tmp_path):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "PowerShell",
        "tool_input": {"command": "Remove-Item $x", "description": "cleanup"},
        "cwd": str(tmp_path),
    }
    out = io.StringIO()
    rc = run_pretooluse(io.StringIO(json.dumps(payload)), out)
    assert rc == 0
    resp = json.loads(out.getvalue())["hookSpecificOutput"]
    assert resp["permissionDecision"] == "deny"
    assert "updatedInput" not in resp


def test_claude_hook_rewrites_in_shadow_mode_too(tmp_path):
    if not syscall_guard.available():
        pytest.skip("Linux x86-64 syscall guard not available")
    (tmp_path / ".demo_cli.toml").write_text('mode = "shadow"\n')
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm $(cat list.txt)"},
        "cwd": str(tmp_path),
    }
    out = io.StringIO()
    rc = run_pretooluse(io.StringIO(json.dumps(payload)), out)
    assert rc == 0
    # B1b (msg 043): the rewrite is now "<launcher> sh -g <id> <quoted cmd>" and carries no permissionDecision.
    resp = json.loads(out.getvalue())["hookSpecificOutput"]
    assert "permissionDecision" not in resp
    assert "updatedInput" in resp


# ==============================================================================
# 4. Behavioral syscall guard runtime tests (Linux x86-64 only)
# ==============================================================================

@pytest.mark.skipif(not syscall_guard.available(), reason="Linux x86-64 ptrace required")
def test_syscall_guard_catches_inplace_overwrite_and_restores(tmp_path):
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    victim = tmp_path / "v.txt"
    victim.write_text("ORIGINAL_CONTENT")

    cmd = [sys.executable, "-c", f"f=open({repr(str(victim))}, 'r+'); f.write('MODIFIED'); f.close()"]
    rc = syscall_guard.run_supervised(cmd, config=cfg)
    assert rc == 0
    assert victim.read_text().startswith("MODIFIED")

    # Verify a snapshot was taken and restore returns exact original bytes
    index = [json.loads(line) for line in open(recovery._index_path(cfg.recovery_dir))]
    assert any("openat_modify" in e.get("action", "") or "v.txt" in e.get("action", "") for e in index)

    entry = index[-1]
    res = recovery.restore(entry)
    assert res.ok is True
    assert victim.read_text() == "ORIGINAL_CONTENT"


@pytest.mark.skipif(not syscall_guard.available(), reason="Linux x86-64 ptrace required")
def test_syscall_guard_append_is_not_snapshotted(tmp_path):
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    log = tmp_path / "app.log"
    log.write_text("initial\n")

    cmd = [sys.executable, "-c", f"f=open({repr(str(log))}, 'a'); f.write('more\\n'); f.close()"]
    rc = syscall_guard.run_supervised(cmd, config=cfg)
    assert rc == 0
    assert log.read_text() == "initial\nmore\n"

    # Append is not destructive: no snapshot index should exist
    assert not os.path.exists(recovery._index_path(cfg.recovery_dir))


@pytest.mark.skipif(not syscall_guard.available(), reason="Linux x86-64 ptrace required")
def test_syscall_guard_background_process_does_not_freeze(tmp_path):
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    pid_file = tmp_path / "pid.txt"
    marker = tmp_path / "marker.txt"

    # Background job sleeps 6s then writes marker
    cmd = ["bash", "-c", f"(sleep 6 && echo alive > {marker}) & echo $! > {pid_file}"]
    t0 = time.perf_counter()
    rc = syscall_guard.run_supervised(cmd, config=cfg)
    t1 = time.perf_counter()

    assert rc == 0
    assert (t1 - t0) < 4.0, f"run_supervised took {t1 - t0:.2f}s instead of returning under 4s"
    assert pid_file.exists()
    bg_pid = int(pid_file.read_text().strip())

    # Check process state from /proc/<pid>/stat: must NOT be in state T (stopped)
    time.sleep(0.3)
    try:
        stat_content = open(f"/proc/{bg_pid}/stat").read()
        proc_state = stat_content[stat_content.rfind(")") + 2]
    except OSError:
        proc_state = "Z"

    assert proc_state not in ("T", "t"), f"background pid {bg_pid} is frozen in stopped state {proc_state}"

    # Wait for the background job to finish writing marker (up to 8s total)
    for _ in range(80):
        if marker.exists():
            break
        time.sleep(0.1)

    try:
        assert marker.exists(), f"background process {bg_pid} did not execute; marker was never written"
        assert marker.read_text().strip() == "alive"
    finally:
        try:
            os.kill(bg_pid, signal.SIGKILL)
        except OSError:
            pass


@pytest.mark.skipif(not syscall_guard.available(), reason="Linux x86-64 ptrace required")
def test_syscall_guard_e2e_delete_and_restore(tmp_path):
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    victim = tmp_path / "del_me.txt"
    victim.write_text("WILL_BE_DELETED")

    cmd = ["bash", "-c", f"rm {victim}"]
    rc = syscall_guard.run_supervised(cmd, config=cfg)
    assert rc == 0
    assert not victim.exists()

    index = [json.loads(line) for line in open(recovery._index_path(cfg.recovery_dir))]
    assert any("del_me.txt" in e.get("action", "") for e in index)

    res = recovery.restore(index[-1])
    assert res.ok is True
    assert victim.exists()
    assert victim.read_text() == "WILL_BE_DELETED"

