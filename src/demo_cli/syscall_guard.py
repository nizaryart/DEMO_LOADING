"""Behavioral guard: run a command under a syscall monitor and snapshot the
files it is about to destroy - BEFORE the destructive syscall executes.

This is the "obfuscation-proof floor" (REC #6). The pre-execution string guard
(classify.py) reads the command text and is defeated by indirection - obfuscated
commands (#002), a payload hidden in a sourced file (#003), a parser-differential
that mis-counts what bash deletes (#004). This layer does not read the string at
all: it lets the command run under ptrace and reacts to what it *does*. You
cannot obfuscate a syscall - `rm`, however written, becomes `unlink()` on a
kernel-resolved absolute path.

Scope: LOCAL filesystem destruction only, on Linux (ptrace is a Linux feature).
External blast radius (remote DB, force-push) is invisible to a local syscall
monitor and stays on the string guard's escalate path. This is a prototype
mechanism (ptrace, per-syscall stop); the production floor is seccomp-unotify.

It reuses the existing machinery: recovery.snapshot / Target build the backup,
receipts.append_receipt records it (hash-chained), so `demo_cli undo` and
`demo_cli verify` work on these entries exactly like the pre-execution path.

Outside the project (V18 step 2) nothing is backed up and nothing is blocked:
each existing file a destructive syscall reaches there is RECORDED - one
receipt per file per run, temp and pseudo filesystems skipped, at most
_OUTSIDE_CAP receipts per run - so the person can see what unread code
destroyed outside the project.
"""
from __future__ import annotations

import ctypes
import errno
import os
import stat
import sys
import tempfile
import uuid
from typing import Dict, List, Optional, Set

from . import recovery
from .config import Config, control_plane_paths, load_config
from .context import build_context
from .receipts import Receipt, append_receipt

# --------------------------------------------------------------------------
# ptrace / register plumbing (x86-64 Linux)
# --------------------------------------------------------------------------

PTRACE_TRACEME = 0
PTRACE_CONT = 7
PTRACE_SYSCALL = 24
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_DETACH = 17
PTRACE_SETOPTIONS = 0x4200

PTRACE_O_TRACESYSGOOD = 0x00000001
PTRACE_O_TRACEFORK = 0x00000002
PTRACE_O_TRACEVFORK = 0x00000004
PTRACE_O_TRACECLONE = 0x00000008
PTRACE_O_TRACEEXEC = 0x00000010
PTRACE_O_EXITKILL = 0x00100000
_OPTIONS = (PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
            PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL)

AT_FDCWD = -100
O_RDONLY = 0
O_WRONLY = 0o1
O_RDWR = 0o2
O_ACCMODE = 0o3
O_CREAT = 0o100
O_TRUNC = 0o1000
O_APPEND = 0o2000


class _Regs(ctypes.Structure):
    # struct user_regs_struct, x86-64 order.
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
        "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags",
        "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs")]


try:
    _libc = ctypes.CDLL("libc.so.6", use_errno=True)
    _libc.ptrace.restype = ctypes.c_long
    _libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
except Exception:
    _libc = None


def _ptrace(request: int, pid: int, addr: int = 0, data: int = 0) -> int:
    ctypes.set_errno(0)
    res = _libc.ptrace(request, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    e = ctypes.get_errno()
    if res == -1 and e:
        raise OSError(e, os.strerror(e))
    return res


def _getregs(pid: int) -> _Regs:
    regs = _Regs()
    _ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
    return regs


def _setregs(pid: int, regs: _Regs) -> None:
    _ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))


def _arg(regs: _Regs, i: int) -> int:
    # syscall args 1..6 -> rdi rsi rdx r10 r8 r9
    return (regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9)[i]


def _signed(u: int) -> int:
    return u - (1 << 64) if u >= (1 << 63) else u


def _read_cstr(pid: int, addr: int, limit: int = 4096) -> Optional[str]:
    """Read a NUL-terminated string from the tracee's memory via /proc/pid/mem."""
    if not addr:
        return None
    try:
        with open(f"/proc/{pid}/mem", "rb", 0) as mem:
            mem.seek(addr)
            chunk = mem.read(limit)
    except OSError:
        return None
    nul = chunk.find(b"\x00")
    raw = chunk[:nul] if nul != -1 else chunk
    try:
        return raw.decode("utf-8", "surrogateescape")
    except Exception:
        return None


# --------------------------------------------------------------------------
# Which syscalls destroy a file, and where the path argument lives
# --------------------------------------------------------------------------

# nr -> (name, path_arg_index, dirfd_arg_index_or_None)
_DELETE = {
    87:  ("unlink", 0, None),          # unlink(path)
    263: ("unlinkat", 1, 0),           # unlinkat(dirfd, path, flags)
    84:  ("rmdir", 0, None),           # rmdir(path)
    85:  ("creat", 0, None),           # creat(path, mode) - truncates if exists
    76:  ("truncate", 0, None),        # truncate(path, len)
    82:  ("rename", 1, None),          # rename(old, NEW) - dest overwritten
    264: ("renameat", 3, 2),           # renameat(olddirfd, old, newdirfd, NEW)
    316: ("renameat2", 3, 2),          # renameat2(olddirfd, old, newdirfd, NEW, flags)
}
# open-family: truncate an existing file when O_TRUNC is set.
# nr -> (name, path_arg_index, flags_arg_index, dirfd_arg_index_or_None)
_OPEN = {
    2:   ("open", 0, 1, None),         # open(path, flags, mode)
    257: ("openat", 1, 2, 0),          # openat(dirfd, path, flags, mode)
}


def _resolve(pid: int, regs: _Regs, path_idx: int, dirfd_idx: Optional[int]) -> Optional[str]:
    """Resolve the syscall's path argument to an absolute path, honouring a
    dirfd for the *at variants (AT_FDCWD or an open directory fd)."""
    p = _read_cstr(pid, _arg(regs, path_idx))
    if p is None:
        return None
    if os.path.isabs(p):
        return os.path.normpath(p)
    # relative: resolve against the tracee's cwd, or the dirfd for *at calls.
    base = None
    if dirfd_idx is not None:
        dirfd = _signed(_arg(regs, dirfd_idx))
        if dirfd != AT_FDCWD:
            try:
                base = os.readlink(f"/proc/{pid}/fd/{dirfd}")
            except OSError:
                base = None
    if base is None:
        try:
            base = os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            base = os.getcwd()
    return os.path.normpath(os.path.join(base, p))


# --------------------------------------------------------------------------
# Scope filter (avoid the noise problem: only in-project, pre-existing files)
# --------------------------------------------------------------------------

# Shared with fsguard (Windows) and with copytree's exclusion list - see
# recovery.IGNORED_DIRS. Kept as one set so a new entry cannot fix one platform
# and silently miss the other.
_IGNORE_PARTS = recovery.IGNORED_DIRS


def _in_scope(path: str, root: str, workspace: Optional[str] = None) -> bool:
    """In the project, not the project itself, not under an ignored directory,
    and not in our own workspace - which is decided by PATH. A user directory
    that merely shares the workspace's name is in scope (audit R4)."""
    ap = os.path.abspath(path)
    if not recovery.within_project(ap, root):   # by path AND by real path
        return False
    ws = workspace or os.path.join(root, ".demo_cli")
    if recovery._contains(ws, ap):
        return False
    rel_parts = set(os.path.relpath(ap, root).split(os.sep))
    return not (rel_parts & (_IGNORE_PARTS - recovery.WORKSPACE_NAMES))


# --------------------------------------------------------------------------
# The supervisor
# --------------------------------------------------------------------------

# V18 step 2: destroys outside the project are recorded, never backed up nor
# blocked. Temp and pseudo filesystems are skipped (`> /dev/null` truncates a
# device, a build rewrites its own temp files); a run that reaches more files
# than the cap gets one closing receipt instead of a flood.
_OUTSIDE_CAP = 100
_PSEUDO_ROOTS = ("/proc", "/sys", "/dev")


def _temp_roots() -> List[str]:
    roots = [tempfile.gettempdir(), "/tmp", "/var/tmp", "/dev/shm",
             os.environ.get("TMPDIR", ""), os.environ.get("XDG_RUNTIME_DIR", "")]
    out: List[str] = []
    for r in roots:
        if r:
            for q in (os.path.abspath(r), os.path.realpath(r)):
                if q not in out:
                    out.append(q)
    return out


class _Outside:
    """Per-run state for the outside-the-project record."""

    def __init__(self) -> None:
        self.skip = list(_PSEUDO_ROOTS) + _temp_roots()
        self.count = 0

    def skipped(self, ap: str) -> bool:
        # By its own path and by its parent's real path (the file itself may
        # be the link being removed, so it is not resolved).
        real = os.path.join(os.path.realpath(os.path.dirname(ap)), os.path.basename(ap))
        return any(recovery._contains(r, ap) or recovery._contains(r, real) for r in self.skip)


def available() -> bool:
    """True on Linux x86-64 where ptrace is usable."""
    if sys.platform != "linux" or _libc is None:
        return False
    import platform
    if platform.machine() not in ("x86_64", "AMD64"):
        return False
    scope_path = "/proc/sys/kernel/yama/ptrace_scope"
    if os.path.exists(scope_path):
        try:
            val = int(open(scope_path).read().strip())
            if val > 1:
                return False
        except Exception:
            pass
    return True


def _parse_tracer_pid(status_text: str) -> int:
    for line in status_text.splitlines():
        if line.startswith("TracerPid:"):
            try:
                return int(line.split(":", 1)[1].strip())
            except ValueError:
                return 0
    return 0


def _tracer_is_ours(status_text: str, cmdline_bytes: bytes) -> bool:
    pid = _parse_tracer_pid(status_text)
    if pid == 0:
        return False
    args = [a.decode("utf-8", errors="replace") for a in cmdline_bytes.split(b"\x00") if a]
    if not args:
        return False

    def _clean(p: str) -> str:
        base = os.path.basename(p.replace("\\", "/")).lower()
        return base.removesuffix(".exe")

    a0 = _clean(args[0])
    # Shape 1: demo_cli (launcher directly executed) sh/run
    if a0 == "demo_cli" and len(args) > 1 and args[1] in ("sh", "run"):
        return True

    # Shapes 2 & 3: python interpreter
    if a0.startswith("python"):
        # Shape 2: python <launcher> sh/run
        if len(args) > 2 and _clean(args[1]) == "demo_cli" and args[2] in ("sh", "run"):
            return True
        # Shape 3: python -m demo_cli sh/run
        if len(args) > 3 and args[1] == "-m" and args[2] == "demo_cli" and args[3] in ("sh", "run"):
            return True

    return False


def _check_tracer() -> tuple[bool, int, str]:
    if sys.platform != "linux":
        return False, 0, ""
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as f:
            status_text = f.read()
    except Exception:
        return False, 0, ""

    tracer_pid = _parse_tracer_pid(status_text)
    if tracer_pid == 0:
        return False, 0, ""

    try:
        with open(f"/proc/{tracer_pid}/cmdline", "rb") as f:
            cmdline_bytes = f.read()
    except Exception:
        cmdline_bytes = b""

    argv0 = ""
    if cmdline_bytes:
        raw_parts = [p.decode("utf-8", errors="replace") for p in cmdline_bytes.split(b"\x00") if p]
        if raw_parts:
            argv0 = raw_parts[0]

    is_ours = _tracer_is_ours(status_text, cmdline_bytes)
    return is_ours, tracer_pid, argv0


def _is_traced() -> bool:
    return _check_tracer()[1] != 0


def run_supervised(argv: List[str], config: Optional[Config] = None,
                   deny: bool = False, group: Optional[str] = None) -> int:
    """Fork+exec argv under ptrace; snapshot any in-scope, pre-existing file a
    destructive syscall is about to touch, then let it proceed (snapshot-then-
    allow). With deny=True, the destructive syscall is turned into a no-op
    (-EPERM) instead. Returns the child's exit code."""
    if sys.platform != "linux":
        raise RuntimeError("syscall guard requires Linux (ptrace).")
    # If this process is itself already being traced (Linux: TracerPid in /proc/self/status
    # is not 0), direct exec is permitted ONLY if the tracer is a demo_cli supervisor.
    # If traced by a foreign process (strace, gdb, etc.), refuse to run unsupervised (exit 126).
    is_ours, tracer_pid, argv0 = _check_tracer()
    if tracer_pid != 0:
        if is_ours:
            try:
                os.execvp(argv[0], argv)
            except OSError as exc:
                os.write(2, f"demo_cli run: cannot exec {argv[0]!r}: {exc}\n".encode())
                os._exit(127)
        else:
            sys.stderr.write(
                f"demo_cli sh: already traced by another process (pid {tracer_pid}: {argv0}); refusing to run unsupervised\n"
            )
            sys.exit(126)
    config = config or load_config()
    group = group or uuid.uuid4().hex[:8]
    root = os.path.abspath(config.project_root or os.getcwd())
    env = build_context(" ".join(argv), cwd=root).environment
    raw_planes = control_plane_paths(config)
    planes = list(dict.fromkeys([os.path.realpath(p) for p in raw_planes] + list(raw_planes)))

    pid = os.fork()
    if pid == 0:                                   # child
        _ptrace(PTRACE_TRACEME, 0)
        try:
            os.execvp(argv[0], argv)
        except OSError as exc:
            os.write(2, f"demo_cli run: cannot exec {argv[0]!r}: {exc}\n".encode())
            os._exit(127)

    # parent: the reference monitor
    os.waitpid(pid, 0)                             # initial exec-stop
    _ptrace(PTRACE_SETOPTIONS, pid, 0, _OPTIONS)
    _ptrace(PTRACE_SYSCALL, pid)

    created: Set[str] = set()                      # files the command itself created
    snapped: Set[str] = set()                      # dedupe snapshots per path
    outside = _Outside()                           # V18: outside-the-project record
    active_pids: Set[int] = {pid}
    child_rc = 0

    while True:
        try:
            wpid, status = os.waitpid(-1, 0)
        except ChildProcessError:
            break
        if wpid not in active_pids and not (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
            active_pids.add(wpid)
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            active_pids.discard(wpid)
            if wpid == pid:
                child_rc = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)
                # Detach from all remaining background tracees
                import signal
                for other in list(active_pids):
                    try:
                        try:
                            _ptrace(PTRACE_DETACH, other, 0, 0)
                        except OSError:
                            os.kill(other, signal.SIGSTOP)
                            os.waitpid(other, 0)
                            _ptrace(PTRACE_DETACH, other, 0, 0)
                        # Resume background processes: waitpid or pending signal delivery
                        # can leave the process in a stopped state (state T). Sending SIGCONT
                        # after detach ensures the background process continues executing.
                        try:
                            os.kill(other, signal.SIGCONT)
                        except OSError:
                            pass
                    except OSError:
                        pass
                break
            continue

        sig = os.WSTOPSIG(status) if os.WIFSTOPPED(status) else 0
        if sig == (5 | 0x80):                       # syscall-stop (SIGTRAP|0x80)
            _maybe_snapshot(wpid, root, created, snapped, env, config, deny, group, planes,
                            outside)
        # ptrace-event / SIGSTOP / SIGTRAP control stops are just resumed; a
        # prototype does not need full signal-forwarding fidelity.
        try:
            _ptrace(PTRACE_SYSCALL, wpid, 0, 0)
        except OSError:
            pass                                    # tracee already gone

    return child_rc


_ENOSYS = ctypes.c_ulonglong(-errno.ENOSYS).value   # rax value at syscall-ENTRY


def _maybe_snapshot(pid: int, root: str, created: Set[str], snapped: Set[str],
                    env: str, config: Config, deny: bool,
                    group: Optional[str] = None,
                    planes: Optional[List[str]] = None,
                    outside: Optional[_Outside] = None) -> None:
    """On a syscall stop: act only at ENTRY (rax == -ENOSYS, the reliable
    entry/exit discriminator) and only for a destructive file syscall on an
    in-scope, pre-existing file - snapshot it (and optionally deny). Outside
    the project, a pre-existing file is recorded only (V18 step 2)."""
    try:
        regs = _getregs(pid)
    except OSError:
        return
    if regs.rax != _ENOSYS:
        return                                       # syscall-exit stop - ignore
    nr = regs.orig_rax

    cands: List[str] = []
    name: Optional[str] = None
    is_destruct = False

    # Track files the command creates, so we never snapshot its own temp files.
    if nr in _OPEN:
        _name, p_idx, f_idx, d_idx = _OPEN[nr]
        flags = _arg(regs, f_idx)
        path = _resolve(pid, regs, p_idx, d_idx)
        if not path:
            return
        abs_p = os.path.abspath(path)
        if (flags & O_CREAT) and not os.path.exists(abs_p):
            created.add(abs_p)
            cands.append(abs_p)
        if flags & O_TRUNC:
            name = "openat_trunc"
            is_destruct = True
            cands.append(abs_p)
        elif (flags & O_ACCMODE) in (O_WRONLY, O_RDWR):
            cands.append(abs_p)
            if not (flags & O_APPEND):
                name = "openat_modify"
                is_destruct = True
    elif nr in _DELETE:
        name, p_idx, d_idx = _DELETE[nr]
        path = _resolve(pid, regs, p_idx, d_idx)
        if path:
            abs_p = os.path.abspath(path)
            cands.append(abs_p)
            is_destruct = True
            if name == "rename":
                src = _resolve(pid, regs, 0, None)
                if src:
                    cands.append(os.path.abspath(src))
            elif name in ("renameat", "renameat2"):
                src = _resolve(pid, regs, 1, 0)
                if src:
                    cands.append(os.path.abspath(src))
    else:
        return

    # 1. Control plane check: REFUSE writes/destructions to demo_cli's own files
    if planes:
        for cand in cands:
            rcand = os.path.realpath(cand)
            if any(recovery._related(cand, q) or recovery._related(rcand, q) for q in planes):
                regs.orig_rax = ctypes.c_ulonglong(-1).value
                try:
                    _setregs(pid, regs)
                except OSError:
                    pass
                decision = "ESCALATE"
                reason = "an agent may not change demo_cli's own files (behavioral guard)"
                append_receipt(config.receipts_path, Receipt(
                    action_raw=f"[syscall] {name or 'write'} {cand}",
                    action_type="syscall",
                    target_environment=env,
                    decision=decision,
                    reason=reason,
                    mode="enforce-syscall",
                    matched_rule="control_plane",
                    classification="destructive",
                    recovery_point=None,
                    agent_id="syscall-guard",
                    session_id="run",
                    group_id=group,
                ))
                sys.stderr.write(f"demo_cli [syscall] {decision}: {name or 'write'} {cand}\n")
                return

    if not is_destruct or not path:
        return
    ap = os.path.abspath(path)
    if ap in created or ap in snapped:
        return
    if not _in_scope(ap, root, config.workspace):
        if outside is not None:
            # The file the syscall destroys: an open follows a link to its
            # target; unlink / rename remove the name itself.
            dp = (os.path.realpath(ap) if name.startswith("openat") else
                  os.path.join(os.path.realpath(os.path.dirname(ap)), os.path.basename(ap)))
            if not (recovery._contains(root, dp) or recovery._contains(os.path.realpath(root), dp)):
                _record_outside(dp, name, snapped, env, config, group, outside)
        return
    if not os.path.exists(ap):
        return                                     # nothing to lose (or already handled)

    snapped.add(ap)
    if deny:
        # Block: turn the syscall into a no-op (invalid nr -> the kernel returns
        # -ENOSYS), so the destruction never happens. No snapshot needed - there
        # is nothing to recover.
        regs.orig_rax = ctypes.c_ulonglong(-1).value
        try:
            _setregs(pid, regs)
        except OSError:
            pass
        dec_entry = None
        decision, reason = "ESCALATE", f"{name} on {ap} blocked before it ran (behavioral guard)."
    else:
        target = recovery.Target("dir" if os.path.isdir(ap) else "file", ap, ap)
        strategy = (config.match_target(ap).recovery if config.match_target(ap) else "snapshot")
        dec_entry = recovery.snapshot(target, config.recovery_dir, strategy,
                                      action=f"{name} {os.path.basename(ap)}",
                                      group=group)
        if dec_entry:
            decision, reason = "REVERSIBLE", f"Snapshotted before {name}; reversible (behavioral guard)."
        else:
            decision, reason = "ESCALATE", f"Could not snapshot {ap} before {name}."

    append_receipt(config.receipts_path, Receipt(
        action_raw=f"[syscall] {name} {ap}",
        action_type="syscall",
        target_environment=env,
        decision=decision,
        reason=reason,
        mode="enforce-syscall",
        matched_rule=f"sys_{name}",
        classification="destructive",
        recovery_point=dec_entry["recovery_point"] if dec_entry else None,
        agent_id="syscall-guard",
        session_id="run",
        group_id=group,
    ))
    undo_id = group or (dec_entry['id'] if dec_entry else "")
    sys.stderr.write(f"demo_cli [syscall] {decision}: {name} {ap}"
                     + (f"  (undo: demo_cli undo {undo_id})" if dec_entry else "") + "\n")


def _record_outside(ap: str, name: str, snapped: Set[str], env: str,
                    config: Config, group: Optional[str], outside: _Outside) -> None:
    """V18 step 2: a destructive syscall on an existing file outside the
    project is let through (never blocked, even with deny) and recorded - no
    backup, so the receipt says it cannot be undone."""
    if ap in snapped or outside.count > _OUTSIDE_CAP or outside.skipped(ap):
        return
    try:
        st = os.lstat(ap)
    except OSError:
        return                                     # nothing there to lose
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode)):
        return                                     # a device, pipe or socket
    snapped.add(ap)
    outside.count += 1
    if outside.count > _OUTSIDE_CAP:
        action = "[syscall] more destroys outside the project"
        reason = (f"More than {_OUTSIDE_CAP} files outside the project were destroyed "
                  "in this run; the rest are not listed (behavioral guard).")
        rule = "sys_outside_cap"
    else:
        action = f"[syscall] {name} {ap}"
        reason = (f"{name} on {ap}: outside the project - recorded, not backed up, "
                  "cannot be undone (behavioral guard).")
        rule = f"sys_outside_{name}"
    append_receipt(config.receipts_path, Receipt(
        action_raw=action,
        action_type="syscall",
        target_environment=env,
        decision="ALLOW",
        reason=reason,
        mode="enforce-syscall",
        matched_rule=rule,
        classification="destructive",
        recovery_point=None,
        agent_id="syscall-guard",
        session_id="run",
        group_id=group,
    ))
    sys.stderr.write("demo_cli [syscall] RECORDED (outside the project, not backed up): "
                     + (f"{name} {ap}" if rule != "sys_outside_cap" else "more files, not listed")
                     + "\n")
