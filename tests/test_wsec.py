"""W-SEC: nothing the user can write runs elevated (rulings R1-R4, Nizar,
2026-10-08; vulnerability log V1-V5).

The logon task used to run %LOCALAPPDATA%\\demo_cli\\autostart-<slug>.cmd,
which called `demo_cli` from PATH - a user-writable script, launcher, venv,
editable checkout, PATH and log, all run ELEVATED. Now: a locked
%ProgramData%\\demo_cli holding a copy of the runtime, the BASE interpreter
with -I, a task registered from XML with a security descriptor, and doctor
rows that flag the old shape.

What needs an elevated Windows session (schtasks /create, icacls on
ProgramData) is checked by Nizar's Windows run; these tests check every
decision the code makes, on any OS.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from demo_cli import protect, schedule

OLD_XML = """<Task><Actions Context="Author"><Exec>
<Command>"C:\\Users\\pc\\AppData\\Local\\demo_cli\\autostart-C-x.cmd"</Command>
</Exec></Actions></Task>"""


@pytest.fixture
def home(tmp_path, monkeypatch):
    """ProgramData, the user's profile and LOCALAPPDATA in tmp_path."""
    pd, prof = tmp_path / "ProgramData", tmp_path / "Users" / "pc"
    (prof / "AppData" / "Local").mkdir(parents=True)
    pd.mkdir()
    monkeypatch.setenv("ProgramData", str(pd))
    monkeypatch.setenv("PROGRAMDATA", str(pd))
    monkeypatch.setenv("USERPROFILE", str(prof))
    monkeypatch.setenv("LOCALAPPDATA", str(prof / "AppData" / "Local"))
    monkeypatch.setenv("APPDATA", str(prof / "AppData" / "Roaming"))
    # tmp_path itself may lie in the real user's temp: point TEMP / TMP at the
    # fake profile so the "user-writable" judgement sees only the fixture
    monkeypatch.setenv("TEMP", str(prof / "AppData" / "Local" / "Temp"))
    monkeypatch.setenv("TMP", str(prof / "AppData" / "Local" / "Temp"))
    return tmp_path


def test_1_the_task_runs_only_locked_absolute_things(home):
    interp = str(home / "Python314" / "python.exe")
    xml = schedule.task_xml(str(home / "proj"), str(home / "proj.real"), interp, "PC\\pc")
    runner = os.path.join(schedule.root(), "runtime", "run.py")
    assert f"<Command>{interp}</Command>" in xml
    assert f'-I &quot;{runner}&quot;' in xml or f'-I "{runner}"' in xml
    assert "<RunLevel>HighestAvailable</RunLevel>" in xml                  # R3: kept
    assert f"<SecurityDescriptor>{schedule.TASK_SDDL}</SecurityDescriptor>" in xml
    assert schedule.TASK_SDDL == "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;AU)"
    assert ".cmd" not in xml and schedule.legacy_dir() not in xml          # V1, V4
    assert os.path.join(schedule.root(), "logs") in xml                     # the log is locked too
    assert schedule.action_is_legacy(xml) is False
    assert schedule.action_is_legacy(OLD_XML) is True


def test_2_an_interpreter_in_the_users_profile_is_never_run_elevated(home, monkeypatch):
    prof = os.environ["USERPROFILE"]
    assert schedule.user_writable_location(os.path.join(prof, "AppData", "Local", "pipx",
                                                        "venvs", "demo-cli", "python.exe"))
    assert schedule.user_writable_location(os.path.join(prof, "Desktop", "x"))
    assert not schedule.user_writable_location(str(home / "Python314" / "python.exe"))
    # register refuses before writing anything
    monkeypatch.setattr(schedule, "available", lambda: True)
    monkeypatch.setattr(protect, "is_elevated", lambda: True)
    monkeypatch.setattr(schedule, "base_interpreter",
                        lambda: os.path.join(prof, "AppData", "Local", "Programs", "python.exe"))
    calls = []
    monkeypatch.setattr(schedule, "_run", lambda args: calls.append(args))
    assert schedule.register(str(home / "proj"), str(home / "proj.real")) is False
    assert calls == []
    assert not os.path.exists(schedule.root())


def test_3_only_the_elevated_step_registers(home, monkeypatch):
    monkeypatch.setattr(schedule, "available", lambda: True)
    monkeypatch.setattr(protect, "is_elevated", lambda: False)
    calls = []
    monkeypatch.setattr(schedule, "_run", lambda args: calls.append(args))
    assert schedule.register(str(home / "proj"), str(home / "proj.real")) is False
    assert calls == []


def test_4_a_link_in_place_of_the_task_home_is_refused(home, monkeypatch):
    target = home / "elsewhere"
    target.mkdir()
    monkeypatch.setattr(protect, "_is_reparse_point", lambda p: os.path.normcase(p) ==
                        os.path.normcase(schedule.root()))
    os.makedirs(schedule.root())
    ok, why = schedule.stage_runtime()
    assert ok is False and "link" in why


def test_5_the_runtime_copy_runs_without_the_installed_package(home, monkeypatch):
    """stage_runtime copies demo_cli (+ the mount's modules when present) into
    the locked home; run.py starts THAT copy, isolated (-I)."""
    monkeypatch.setattr(protect, "lock_readable", lambda p: protect.ResetOutcome(True))
    ok, why = schedule.stage_runtime()
    assert (ok, why) == (True, "")
    site = Path(schedule.root()) / "runtime" / "site"
    assert (site / "demo_cli" / "cli.py").is_file()
    assert not list(site.rglob("__pycache__"))
    runner = Path(schedule.root()) / "runtime" / "run.py"
    log = home / "run.log"
    r = subprocess.run([sys.executable, "-I", str(runner), "--log", str(log), "--version"],
                       capture_output=True, text=True, timeout=120, cwd=str(home))
    from demo_cli.version import __version__
    assert __version__ in log.read_text(encoding="utf-8")
    assert r.returncode == 0


def test_6_doctor_flags_the_old_task(home, monkeypatch):
    class R:
        returncode, stdout = 0, OLD_XML
    monkeypatch.setattr(schedule, "available", lambda: True)
    monkeypatch.setattr(schedule, "_run", lambda args: R())
    rows = schedule.audit(str(home / "proj"))
    assert len(rows) == 1 and rows[0][0] == "fail"
    assert "ELEVATED" in rows[0][2] and "setup" in rows[0][2]
    st = schedule.status(str(home / "proj"))
    assert st.exists is True and st.legacy is True


def test_7_the_task_homes_are_demo_clis_own(home):
    """Ruling R4: config.control_plane_paths adds these on Windows."""
    assert schedule.control_plane_paths() == [schedule.root(), schedule.legacy_dir()]
    assert schedule.root() == os.path.join(str(home / "ProgramData"), "demo_cli")


def test_8_nobody_but_administrators_may_write():
    A = protect.Ace
    users_rx = A(protect.USERS_SID, True, 0x1200A9, 0x3)
    users_w = A(protect.USERS_SID, True, 0x1301BF, 0x3)
    admins = A(protect.ADMINS_SID, True, 0x1F01FF, 0x3)
    assert protect.nobody_else_writes([admins, users_rx]) is True
    assert protect.nobody_else_writes([admins, users_w]) is False
    assert protect.nobody_else_writes(None) is None
    assert protect._READABLE_LOCK_ACL == [(protect.SYSTEM_SID, "(OI)(CI)F"),
                                          (protect.ADMINS_SID, "(OI)(CI)F"),
                                          (protect.USERS_SID, "(OI)(CI)RX")]
