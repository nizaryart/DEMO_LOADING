import io
import json
import os
import sys
from types import SimpleNamespace

import pytest
from conftest import assert_restores

from demo_cli import doctor, recovery, syscall_guard
from demo_cli.config import Config, load_config
from demo_cli.decide import ESCALATE
from demo_cli.guard import Guard
from demo_cli.hooks.claude_code import run_pretooluse
from demo_cli.protection import THREAT_MODEL


def test_1_unknown_mode_is_config_error(tmp_path):
    bad_cfg = tmp_path / "bad"
    bad_cfg.mkdir()
    (bad_cfg / ".demo_cli.toml").write_text('mode = "enforcing"\n')
    cfg = load_config(str(bad_cfg))
    assert cfg.config_error is not None
    assert "mode = 'enforcing' is not one of: shadow, enforce" in cfg.config_error
    g = Guard(config=cfg)
    res = g.evaluate("ls")
    assert res.decision.decision == ESCALATE
    assert "mode = 'enforcing' is not one of: shadow, enforce" in res.decision.reason

    c1 = tmp_path / "c1"
    c1.mkdir()
    (c1 / ".demo_cli.toml").write_text('mode = "Enforce"\n')
    cfg1 = load_config(str(c1))
    assert cfg1.config_error is None
    assert cfg1.mode == "enforce"

    c2 = tmp_path / "c2"
    c2.mkdir()
    (c2 / ".demo_cli.toml").write_text('[workspace]\ndir = ".demo_cli"\n')
    cfg2 = load_config(str(c2))
    assert cfg2.config_error is None
    assert cfg2.mode == "shadow"


def test_2_unknown_egress_mode_is_config_error(tmp_path):
    bad = tmp_path / "bad_egress"
    bad.mkdir()
    (bad / ".demo_cli.toml").write_text('[egress]\nmode = "blocking"\n')
    cfg = load_config(str(bad))
    assert cfg.config_error is not None
    assert "[egress] mode = 'blocking' is not one of: shadow, enforce" in cfg.config_error

    ok = tmp_path / "ok_egress"
    ok.mkdir()
    (ok / ".demo_cli.toml").write_text('[egress]\nmode = "shadow"\n')
    cfg_ok = load_config(str(ok))
    assert cfg_ok.config_error is None


def test_3_doctor_output_shows_bad_mode_error(tmp_path, capsys):
    (tmp_path / ".demo_cli.toml").write_text('mode = "invalid_mode"\n')
    rc = doctor.cmd_doctor(SimpleNamespace(root=str(tmp_path)))
    assert rc == 1
    out = capsys.readouterr().out
    assert "mode = 'invalid_mode' is not one of: shadow, enforce" in out


def test_4_claude_code_hook_enforce(tmp_path):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')

    # 1. ls -> stdout ""
    out_ls = io.StringIO()
    rc_ls = run_pretooluse(io.StringIO(json.dumps({
        "tool_name": "Bash", "cwd": str(tmp_path),
        "tool_input": {"command": "ls"}
    })), out_ls)
    assert rc_ls == 0
    assert out_ls.getvalue() == ""

    # 2. rm a.txt (existing file) -> no permissionDecision;
    #    additionalContext and systemMessage both contain recovery point;
    #    assert_restores on the entry
    a_file = tmp_path / "a.txt"
    a_file.write_text("hello")
    out_rm = io.StringIO()
    rc_rm = run_pretooluse(io.StringIO(json.dumps({
        "tool_name": "Bash", "cwd": str(tmp_path),
        "tool_input": {"command": "rm a.txt"}
    })), out_rm)
    assert rc_rm == 0
    data_rm = json.loads(out_rm.getvalue())
    hso_rm = data_rm["hookSpecificOutput"]
    assert "permissionDecision" not in hso_rm
    assert "recovery point" in hso_rm["additionalContext"]
    assert "recovery point" in data_rm["systemMessage"]
    rec_dir = os.path.join(str(tmp_path), ".demo_cli", "recovery")
    entries = recovery.load_entries(rec_dir)
    assert len(entries) == 1
    assert_restores(entries[0], str(tmp_path), {"a.txt": b"hello"})

    # 3. terraform destroy -> deny (control, unchanged)
    out_tf = io.StringIO()
    rc_tf = run_pretooluse(io.StringIO(json.dumps({
        "tool_name": "Bash", "cwd": str(tmp_path),
        "tool_input": {"command": "terraform destroy"}
    })), out_tf)
    assert rc_tf == 0
    data_tf = json.loads(out_tf.getvalue())
    hso_tf = data_tf["hookSpecificOutput"]
    assert hso_tf["permissionDecision"] == "deny"

    # 4. an Edit of an existing file -> the capture shape
    exist_f = tmp_path / "exist.txt"
    exist_f.write_text("before")
    out_ee = io.StringIO()
    rc_ee = run_pretooluse(io.StringIO(json.dumps({
        "tool_name": "Edit", "cwd": str(tmp_path),
        "tool_input": {"file_path": str(exist_f)}
    })), out_ee)
    assert rc_ee == 0
    data_ee = json.loads(out_ee.getvalue())
    hso_ee = data_ee["hookSpecificOutput"]
    assert "permissionDecision" not in hso_ee
    assert "recovery point" in hso_ee["additionalContext"]
    assert "recovery point" in data_ee["systemMessage"]

    # 5. an Edit of a new file -> ""
    new_f = tmp_path / "new_file.txt"
    out_en = io.StringIO()
    rc_en = run_pretooluse(io.StringIO(json.dumps({
        "tool_name": "Edit", "cwd": str(tmp_path),
        "tool_input": {"file_path": str(new_f)}
    })), out_en)
    assert rc_en == 0
    assert out_en.getvalue() == ""


def test_5_claude_code_hook_shadow(tmp_path):
    (tmp_path / ".demo_cli.toml").write_text('mode = "shadow"\n')

    # ls -> ""
    out_ls = io.StringIO()
    rc_ls = run_pretooluse(io.StringIO(json.dumps({
        "tool_name": "Bash", "cwd": str(tmp_path),
        "tool_input": {"command": "ls"}
    })), out_ls)
    assert rc_ls == 0
    assert out_ls.getvalue() == ""

    # rm a.txt -> ""
    a_file = tmp_path / "a.txt"
    a_file.write_text("hello")
    out_rm = io.StringIO()
    rc_rm = run_pretooluse(io.StringIO(json.dumps({
        "tool_name": "Bash", "cwd": str(tmp_path),
        "tool_input": {"command": "rm a.txt"}
    })), out_rm)
    assert rc_rm == 0
    assert out_rm.getvalue() == ""


@pytest.mark.skipif(not syscall_guard.available(), reason="Linux x86-64 ptrace required")
def test_6_shadow_syscall_guard_refusal_and_threat_model(tmp_path):
    cfg_file = tmp_path / ".demo_cli.toml"
    cfg_file.write_text('mode = "shadow"\n')
    cfg = Config(project_root=str(tmp_path), mode="shadow")

    cmd = [sys.executable, "-c", f"f = open({repr(str(cfg_file))}, 'w'); f.write('evil'); f.close()"]
    rc = syscall_guard.run_supervised(cmd, config=cfg)
    assert rc != 0
    assert cfg_file.read_text() == 'mode = "shadow"\n'

    assert "The runtime net runs in both modes" in THREAT_MODEL
