"""M2.2d: code that runs later, unnamed - a shell startup file, a git hook,
.envrc, a git config key git runs, a cron / at / scheduled task, an enabled
unit, a registry Run key - as one effect kind (LATER) on one surface
(deferred_execution, ask), and the shell-guard startup file in the control
plane (rulings D1-D5, Nizar, 2026-10-08).

Rows and expected results in tests/fixtures/m22d/, measured by ORCH on the
prototype on Linux and Windows Python 3.14 with HOME / USERPROFILE pointed at
a fresh home. The SUPERVISED row (`git -c core.pager=... log`: not
understood, so today's path and the runtime net decide it) differs by machine
and is checked by its uncovered / remote fields.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from demo_cli import policy
from demo_cli.config import Config
from demo_cli.guard import Guard, agent_directory

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "m22d"
FIX = {"a.txt": "A", "package.json": '{"scripts": {"test": "x"}}\n', "Makefile": "all:\n",
       ".git/hooks/pre-commit.sample": "#!/bin/sh\n", ".git/hooks/post-merge": "#!/bin/sh\n",
       "sub/s.txt": "s", "job.sh": "echo hi\n", "x.cron": "* * * * * echo hi\n",
       "evil.sh": "echo evil\n", "unit.service": "[Unit]\n"}


def _make(tmp: Path, monkeypatch, guard_line: bool = False) -> Path:
    home, proj = tmp / "home", tmp / "proj"
    home.mkdir(parents=True)
    rc = "alias ll='ls -l'\n"
    if guard_line:
        rc += f"export BASH_ENV={home.as_posix()}/.demo_cli_shellguard.sh\n"
    (home / ".bashrc").write_text(rc)
    for rel, body in FIX.items():
        (proj / rel).parent.mkdir(parents=True, exist_ok=True)
        (proj / rel).write_bytes(body.encode())
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return proj


def _evaluate(proj: Path, cmd: str):
    cfg = Config(project_root=str(proj), mode="enforce")
    with agent_directory(str(proj)):
        return Guard(cfg).evaluate(cmd, door="agent", can_supervise=True)


def test_1_rows(tmp_path: Path, monkeypatch):
    rows = json.load(open(FIXTURES / "rows_input.json"))
    expected = json.load(open(FIXTURES / "expected_rows.json"))
    assert len(rows) == len(expected) == 72
    for idx, row in enumerate(rows):
        cmd = row["cmd"]
        exp = expected[cmd]
        proj = _make(tmp_path / f"r_{idx}", monkeypatch)
        r = _evaluate(proj, cmd)
        assert ((r.prediction or {}).get("uncovered") or []) == exp["uncovered"], cmd
        assert ((r.prediction or {}).get("remote") or {}) == exp["remote"], cmd
        if exp["decision"] == "SUPERVISED":
            continue        # decided by today's path + the runtime net: machine-dependent
        assert r.decision.decision == exp["decision"], cmd
        assert r.classification.nonrecoverable_surface == exp["surface"], cmd
        assert r.decision.approvable is exp["approvable"], cmd
        assert (r.recovery_entry is not None) == exp["captured"], cmd


def test_2_one_kind_one_surface_and_a_person_may_approve_it():
    from demo_cli.engine.effects import LATER
    assert policy.REMOTE_POLICY[LATER] == policy.ESCALATE
    assert policy.surface_of("later:crontab@local") == "deferred_execution"
    assert policy.may_ask("deferred_execution") is True
    assert policy.recovery_hint("deferred_execution").startswith("remove what was planted")


def test_3_the_shell_guard_startup_file_is_demo_clis_own(tmp_path: Path, monkeypatch):
    """Ruling D3: with the shell-guard line in ~/.bashrc, an agent may not
    change that file at all (the guard of every later shell); without it,
    ~/.bashrc is one more startup file a person is asked about."""
    proj = _make(tmp_path / "guarded", monkeypatch, guard_line=True)
    r = _evaluate(proj, "echo 'unset BASH_ENV' >> ~/.bashrc")
    assert (r.decision.decision, r.decision.approvable) == ("ESCALATE", False)
    assert "demo_cli" in r.decision.reason
    proj = _make(tmp_path / "plain", monkeypatch, guard_line=False)
    r = _evaluate(proj, "echo 'unset BASH_ENV' >> ~/.bashrc")
    assert (r.decision.decision, r.classification.nonrecoverable_surface,
            r.decision.approvable) == ("ESCALATE", "deferred_execution", True)


def test_4_only_places_that_run_code_on_their_own(tmp_path: Path):
    """Ruling D2: auto-run places count; files that run only when someone
    names them (make, npm test, pytest, CI) do not."""
    from demo_cli.engine.deferred import GIT_HOOKS, place
    home = tmp_path / "home"
    proj = tmp_path / "proj"
    yes = [home / ".bashrc", home / ".zshrc", home / ".profile", home / ".gitconfig",
           home / ".config" / "autostart" / "x.desktop",
           home / "Documents" / "PowerShell" / "Microsoft.PowerShell_profile.ps1",
           proj / ".envrc", proj / ".git" / "hooks" / "pre-commit", proj / ".git" / "config"]
    no = [proj / "Makefile", proj / "package.json", proj / "conftest.py",
          proj / ".github" / "workflows" / "ci.yml", proj / ".git" / "hooks" / "pre-commit.sample",
          proj / ".git" / "hooks" / "not-a-hook", proj / ".bashrc", home / ".bash_history",
          home / "Documents" / "PowerShell" / "notes.ps1"]
    for p in yes:
        assert place(str(p), home=str(home)) is not None, p
    for p in no:
        assert place(str(p), home=str(home)) is None, p
    assert len(GIT_HOOKS) == 28 and "pre-commit" in GIT_HOOKS


def test_5_git_config_keys_git_runs(tmp_path: Path, monkeypatch):
    from demo_cli.engine.git_ops import runs_code
    for key in ("core.hooksPath", "CORE.PAGER", "alias.st", "filter.lfs.smudge",
                "credential.https://x.example.helper", "include.path",
                "includeIf.gitdir:~/w/.path", "diff.pdf.textconv", "gpg.ssh.defaultKeyCommand"):
        assert runs_code(key), key
    for key in ("user.email", "core.autocrlf", "gpg.x.defaultKeyCommand", "init.defaultBranch",
                "diff.external.x"):
        assert not runs_code(key), key
    proj = _make(tmp_path / "p", monkeypatch)
    # given for ONE command, the same key runs NOW, unread: not understood
    pr = _evaluate(proj, "git -c core.pager='rm -rf ~' log").prediction or {}
    assert pr.get("remote") == {} and pr.get("unknown")
    assert (_evaluate(proj, "git -c user.name=x status").prediction or {}).get("unknown") == []


def test_6_a_label_reached_twice_keeps_the_worst_kind(tmp_path: Path, monkeypatch):
    """REF was missing from the loss order: `git stash pop && git stash drop`
    raised ValueError in the engine and today's path decided the line."""
    proj = _make(tmp_path / "p", monkeypatch)
    r = _evaluate(proj, "git stash pop && git stash drop")
    assert "error" not in (r.prediction or {})
    assert (r.prediction or {}).get("remote") == {"vcs-local:stash": "DELETE"}
    assert (r.decision.decision, r.classification.nonrecoverable_surface) == (
        "ESCALATE", "local_vcs_history")


def test_7_docker_cp_both_ways(tmp_path: Path, monkeypatch):
    """Ruling D5. VERIFIED with the docker CLI: NAME:PATH is a container."""
    proj = _make(tmp_path / "p", monkeypatch)
    r = _evaluate(proj, "docker cp evil.sh app:/etc/profile")
    assert (r.decision.decision, r.classification.nonrecoverable_surface) == (
        "ESCALATE", "container_runtime")
    r = _evaluate(proj, "docker cp app:/etc/hosts a.txt")
    assert r.decision.decision == "REVERSIBLE"
    assert (proj / "a.txt").read_bytes() == b"A"            # nothing ran: only captured


def test_8_removing_a_place_is_d4_only_for_a_schedule(tmp_path: Path, monkeypatch):
    """Ruling D4 takes away a schedule (a hook git runs). Removing a git
    config, .envrc or a startup file plants nothing: an ordinary local
    change, captured (test_ignored_dir_capture: .git/config named is
    captured)."""
    proj = _make(tmp_path / "p", monkeypatch)
    (proj / ".git" / "config").write_bytes(b"[core]\n")
    (proj / ".envrc").write_bytes(b"export X=1\n")
    for cmd in ("rm .git/config", "rm .envrc"):
        r = _evaluate(proj, cmd)
        assert (r.prediction or {}).get("remote") == {}, cmd
        assert r.decision.decision == "REVERSIBLE", cmd
    r = _evaluate(proj, "rm .git/hooks/post-merge")
    assert (r.prediction or {}).get("remote") == {"later:.git/hooks/post-merge": "DELETE"}
    assert (r.decision.decision, r.classification.nonrecoverable_surface) == (
        "ESCALATE", "deferred_execution")
