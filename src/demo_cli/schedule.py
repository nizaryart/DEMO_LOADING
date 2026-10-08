"""Bring the filesystem guard back after a reboot.

--------------------------------------------------------------------------
WHY THIS EXISTS
--------------------------------------------------------------------------
Shutting down ends the user session, so the mount process dies like any other
program. The FILES are safe - Stage 2 writes straight through to the backing
directory - but two things are not:

  * C:\\project stops existing. It is a reparse point served by a process that
    is gone, so the path an IDE, a shell and git all know simply is not there.
  * The next session is UNPROTECTED. Someone who recreates the directory, or
    works from the backing path instead, is now unguarded while believing they
    are covered - the sixth appearance of that failure in this project.

A logon task removes "I forgot to mount after rebooting" as a possible state.

--------------------------------------------------------------------------
A TASK, NOT A SERVICE
--------------------------------------------------------------------------
A Windows service starts before logon, restarts on crash, and runs as SYSTEM -
more robust, and it means writing service-lifecycle code and registering with
the SCM. A scheduled task is one `schtasks` command to create, one to delete,
and it is VISIBLE in Task Scheduler, so nothing this tool does to the machine
is hidden from the person running it.

`/rl highest` (RunLevel HighestAvailable) because the mount must write a
backing directory locked to Administrators. That elevation is granted once, at
setup, through a UAC prompt the user has already agreed to - not silently.

--------------------------------------------------------------------------
NOTHING THE USER CAN WRITE RUNS ELEVATED (W-SEC, rulings R1-R4, 2026-10-08)
--------------------------------------------------------------------------
The task used to run %LOCALAPPDATA%\\demo_cli\\autostart-<slug>.cmd, which
called `demo_cli` from PATH: a script the user (= the agent) could rewrite, a
launcher from a user-writable pipx venv running an EDITABLE checkout, a user
PATH that decides which demo_cli runs, and a log the elevated task appended to
(V1-V4 in the vulnerability log). Every one of those ran elevated, at logon or
at once with `schtasks /run`, which the user may do without a prompt.

Now, during the already-elevated `_register-task` step:
  * %ProgramData%\\demo_cli is owned by Administrators and locked: SYSTEM and
    Administrators full control, Users read + execute (`lock_readable`). A
    folder that already exists as a link, or that the user created first, is
    refused or taken back before anything is written into it.
  * `runtime\\site` holds a COPY of the demo_cli package and of the modules
    the mount imports (winfspy, cffi, pycparser), and `runtime\\run.py` starts
    it. The copy is the version setup ran; `doctor` flags it when it differs
    from the installed one, and running setup again refreshes it.
  * The task's action is the BASE interpreter (`sys._base_executable`, never
    the venv's), with `-I` (no PYTHONPATH, no user site, not the script's
    directory), on `run.py` - all absolute. An interpreter inside the user's
    profile is refused: there is nothing safe to run.
  * The task is registered from XML with a security descriptor: Users may
    read and run it, never change it.
  * The log lives in `logs\\`, written by the elevated task, readable by the
    user.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple
from xml.sax.saxutils import escape

TASK_PREFIX = "demo_cli guard"

# The modules the mount imports beside demo_cli (fsmount: winfspy, which needs
# cffi; cffi's C parser). Copied with the package into the locked runtime.
RUNTIME_MODULES = ("demo_cli", "winfspy", "cffi", "_cffi_backend", "pycparser")

# The task's own security descriptor: SYSTEM and Administrators full access;
# Authenticated Users read and execute (run it), never write (change it).
TASK_SDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;AU)"


def task_name(project: str) -> str:
    """One task per project, named after it so Task Scheduler is readable.

    Backslashes are the folder separator in the task namespace, so a path
    cannot be used raw - `C:\\Users\\pc\\lab` would create nested folders and
    a task nobody can find again.
    """
    slug = re.sub(r"[^A-Za-z0-9]+", "-", os.path.abspath(project)).strip("-")
    return f"{TASK_PREFIX} - {slug}"


def _slug(project: str) -> str:
    return task_name(project).replace(TASK_PREFIX + " - ", "")


def root() -> str:
    """%ProgramData%\\demo_cli - the locked home of everything the task runs."""
    return os.path.join(os.environ.get("ProgramData") or os.environ.get("PROGRAMDATA")
                        or r"C:\ProgramData", "demo_cli")


def legacy_dir() -> str:
    """Where tasks registered before W-SEC kept their script and log."""
    return os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "demo_cli")


@dataclass
class TaskStatus:
    exists: bool
    name: str
    detail: str = ""
    legacy: bool = False            # registered before W-SEC: re-run setup


def available() -> bool:
    if os.name != "nt":
        return False
    from shutil import which
    return bool(which("schtasks"))


def _run(args: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=60)


def status(project: str) -> TaskStatus:
    name = task_name(project)
    if not available():
        return TaskStatus(False, name, "schtasks unavailable")
    r = _run(["schtasks", "/query", "/tn", name, "/xml"])
    if r.returncode != 0:
        return TaskStatus(False, name, "not registered")
    legacy = action_is_legacy(r.stdout or "")
    return TaskStatus(True, name, "runs at logon" + (" (OLD, user-writable action: run setup "
                                                     "again)" if legacy else ""), legacy)


def action_is_legacy(task_xml: str) -> bool:
    """A task whose action is not this module's locked runtime."""
    m = re.search(r"<Command>(.*?)</Command>", task_xml, re.S)
    a = re.search(r"<Arguments>(.*?)</Arguments>", task_xml, re.S)
    command = (m.group(1) if m else "").strip().strip('"')
    args = a.group(1) if a else ""
    runner = os.path.join(root(), "runtime", "run.py")
    return not (command and os.path.normcase(runner) in os.path.normcase(args)
                and " -I " in f" {args} ")


def user_writable_location(path: str) -> bool:
    """A path inside the user's own profile (or its temp): the user - and so
    an agent - can write there. The base interpreter and the runtime must not
    be. `doctor` checks the real ACL; this is the refusal at registration."""
    p = os.path.normcase(os.path.abspath(path))
    for var in ("USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP"):
        v = os.environ.get(var)
        if v and (p == os.path.normcase(os.path.abspath(v))
                  or p.startswith(os.path.normcase(os.path.abspath(v)).rstrip("\\/") + os.sep)):
            return True
    return False


def base_interpreter() -> Optional[str]:
    """The installation's own python.exe, never a venv's (a venv lives in the
    user's profile): `sys._base_executable`, else <base_prefix>\\python.exe."""
    cand = getattr(sys, "_base_executable", None) or os.path.join(sys.base_prefix, "python.exe")
    if os.name == "nt" and cand and os.path.basename(cand).lower() == "pythonw.exe":
        cand = os.path.join(os.path.dirname(cand), "python.exe")
    return cand if cand and os.path.isfile(cand) else None


def task_xml(project: str, backing: str, interpreter: str, user: str) -> str:
    """The task, as Task Scheduler's XML: a logon trigger for `user`, the
    highest run level, one action - the base interpreter, isolated, on the
    locked runner - and a security descriptor that lets users read and run
    it, never change it."""
    runner = os.path.join(root(), "runtime", "run.py")
    log = os.path.join(root(), "logs", f"{_slug(project)}.log")
    args = (f'-I "{runner}" --log "{log}" mount "{os.path.abspath(project)}" '
            f'--backing "{os.path.abspath(backing)}" --no-wait')
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>demo_cli: bring the filesystem guard back at logon</Description>
    <SecurityDescriptor>{TASK_SDDL}</SecurityDescriptor>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><UserId>{escape(user)}</UserId></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{escape(user)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(interpreter)}</Command>
      <Arguments>{escape(args)}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


RUNNER = '''"""demo_cli's logon runner (written by demo_cli setup; locked: only
Administrators can change it). Runs the COPY of demo_cli in site\\, never the
installed one, which lives where the user can write."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "site"))
args = sys.argv[1:]
if args[:1] == ["--log"]:
    log = open(args[1], "a", encoding="utf-8", buffering=1)
    sys.stdout = sys.stderr = log
    args = args[2:]
from demo_cli.cli import main
sys.exit(main(args))
'''


def _module_path(name: str) -> Optional[str]:
    import importlib.util
    try:
        spec = importlib.util.find_spec(name)
    except (ImportError, ValueError):
        return None
    if spec is None or not spec.origin:
        return None
    if spec.submodule_search_locations:
        return list(spec.submodule_search_locations)[0]
    return spec.origin


def stage_runtime() -> Tuple[bool, str]:
    """Create %ProgramData%\\demo_cli locked, then copy the runtime into it.
    (ok, why). Elevated only."""
    from . import protect
    base = root()
    for p in (base, os.path.join(base, "runtime"), os.path.join(base, "logs")):
        if os.path.lexists(p) and protect._is_reparse_point(p):
            return False, f"{p} is a link or junction - refusing to write through it"
    os.makedirs(base, exist_ok=True)
    if not protect.lock_readable(base):          # owner -> Administrators, ACL reset
        return False, f"could not lock {base}"
    site = os.path.join(base, "runtime", "site")
    if os.path.isdir(site):
        shutil.rmtree(site)
    os.makedirs(site, exist_ok=True)
    os.makedirs(os.path.join(base, "logs"), exist_ok=True)
    for name in RUNTIME_MODULES:
        src = _module_path(name)
        if src is None:
            if name == "demo_cli":
                return False, "the demo_cli package was not found"
            continue                                   # an optional module missing
        dst = os.path.join(site, os.path.basename(src))
        if os.path.isdir(src):
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            shutil.copy2(src, dst)
    with open(os.path.join(base, "runtime", "run.py"), "w", encoding="utf-8") as f:
        f.write(RUNNER)
    if not protect.lock_readable(base):          # the new files inherit; re-applied anyway
        return False, f"could not lock {base}"
    return True, ""


def register(project: str, backing: str, port_free_command: Optional[str] = None) -> bool:
    """Create (or replace) the logon task for one project. Elevated only
    (setup's `_register-task` step). Returns False, writing nothing the task
    would run, when there is no safe interpreter or the folder cannot be
    locked."""
    if not available():
        return False
    from . import protect
    if not protect.is_elevated():
        return False
    project, backing = os.path.abspath(project), os.path.abspath(backing)
    interp = base_interpreter()
    if not interp or user_writable_location(interp):
        return False                                   # nothing safe to run elevated
    ok, _why = stage_runtime()
    if not ok:
        return False
    user = (os.environ.get("USERDOMAIN", "") + "\\" + os.environ.get("USERNAME", "")).strip("\\")
    xml_path = os.path.join(root(), f"task-{_slug(project)}.xml")
    with open(xml_path, "w", encoding="utf-16") as f:
        f.write(task_xml(project, backing, interp, user))
    try:
        r = _run(["schtasks", "/create", "/tn", task_name(project), "/xml", xml_path, "/f"])
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass
    if r.returncode == 0:
        _remove_legacy(project)
    return r.returncode == 0


def _remove_legacy(project: str) -> None:
    for path in legacy_paths(project):
        try:
            os.unlink(path)
        except OSError:
            pass


def run_now(project: str) -> bool:
    """Start the task immediately, without waiting for the next logon.

    This is how setup brings the mount up straight away: the task already
    carries the highest run level, so running it needs no SECOND UAC prompt.
    Since W-SEC what it runs is locked, so this is no longer a way to run the
    user's own code elevated.
    """
    if not available() or not status(project).exists:
        return False
    return _run(["schtasks", "/run", "/tn", task_name(project)]).returncode == 0


def unregister(project: str) -> bool:
    """Remove the task. Absent is success - teardown must never refuse to
    continue because a step was already done."""
    if not available():
        return False
    name = task_name(project)
    ok = True
    if status(project).exists:
        ok = _run(["schtasks", "/delete", "/tn", name, "/f"]).returncode == 0
    for path in autostart_paths(project) + legacy_paths(project):      # leave nothing behind
        try:
            os.unlink(path)
        except OSError:
            pass
    return ok


def autostart_paths(project: str) -> Tuple[str, ...]:
    """The runner and log this project's task uses. Public so teardown can
    remove them and doctor can point at the log."""
    return (os.path.join(root(), "logs", f"{_slug(project)}.log"),)


def legacy_paths(project: str) -> Tuple[str, ...]:
    """The script and log of a task registered before W-SEC."""
    slug = _slug(project)
    return (os.path.join(legacy_dir(), f"autostart-{slug}.cmd"),
            os.path.join(legacy_dir(), f"autostart-{slug}.log"))


def control_plane_paths() -> List[str]:
    """What an agent must never touch, on Windows: the locked task home, and
    the old one (a script there may still be what an old task runs)."""
    return [root(), legacy_dir()]


def audit(project: str) -> List[tuple]:
    """doctor's rows for the logon task (ruling R4): an old task whose action
    the user can rewrite, a task home anyone but Administrators can write, an
    interpreter in the user's profile, a runtime copy older than the
    installed demo_cli."""
    if not available():
        return []
    r = _run(["schtasks", "/query", "/tn", task_name(project), "/xml"])
    if r.returncode != 0:
        return []
    xml = r.stdout or ""
    rows: List[tuple] = []
    if action_is_legacy(xml):
        return [("fail", "logon task",
                 "runs a script the user (and any agent) can rewrite, ELEVATED - run "
                 f"`demo_cli setup {project}` again to replace it")]
    m = re.search(r"<Command>(.*?)</Command>", xml, re.S)
    interp = (m.group(1) if m else "").strip().strip('"')
    if user_writable_location(interp):
        rows.append(("fail", "logon task", f"its interpreter is in the user's profile: {interp}"))
    from . import protect
    locked = protect.nobody_else_writes(protect._read_dacl(root()))
    if locked is False:
        rows.append(("fail", "logon task", f"{root()} is writable by non-administrators"))
    elif locked is None:
        rows.append(("warn", "logon task", f"could not read the ACL of {root()}"))
    try:
        with open(os.path.join(root(), "runtime", "site", "demo_cli", "version.py"),
                  encoding="utf-8") as f:
            staged = re.search(r"__version__\s*=\s*['\"]([^'\"]+)", f.read())
    except OSError:
        staged = None
    from .version import __version__
    if staged is None:
        rows.append(("fail", "logon task", "the locked runtime copy is missing - run setup again"))
    elif staged.group(1) != __version__:
        rows.append(("warn", "logon task", f"runs demo_cli {staged.group(1)}, installed is "
                                           f"{__version__} - run setup again to refresh it"))
    if not rows:
        rows.append(("ok", "logon task", "locked runtime, base interpreter, users may only run it"))
    return rows
