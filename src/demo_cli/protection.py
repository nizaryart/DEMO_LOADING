from __future__ import annotations

from typing import List, Optional, Tuple

THREAT_MODEL = (
    "demo_cli protects against an agent's MISTAKES, not a determined adversary: "
    "commands it understands are judged before they run; for commands it cannot "
    "read, the runtime net (syscall guard on Linux, WinFsp mount on Windows) is "
    "the floor; a remote change that can lose data or cannot be recalled is "
    "stopped for review; one that only adds (a create, a service start) is "
    "allowed and listed."
    " The runtime net runs in both modes: shadow only means that decisions do not block.")


class Facts:
    __slots__ = ("os_name", "agents", "syscall_guard", "mount_running",
                 "checkpoint_enabled")

    def __init__(
        self,
        os_name: str = "posix",
        agents: Tuple[str, ...] = (),
        syscall_guard: bool = False,
        mount_running: Optional[bool] = None,
        checkpoint_enabled: bool = False,
    ):
        self.os_name = os_name
        self.agents = tuple(agents)
        self.syscall_guard = syscall_guard
        self.mount_running = mount_running
        self.checkpoint_enabled = checkpoint_enabled


def rows(f: Facts) -> List[Tuple[str, str, str]]:
    """(status, label, detail) rows, the same shape doctor's checks use."""
    out: List[Tuple[str, str, str]] = [("ok", "threat model", THREAT_MODEL)]
    fallback = (
        "whole-workspace checkpoint"
        if f.checkpoint_enabled
        else "escalated for review"
    )
    is_win = f.os_name in ("Windows", "nt", "win32") or f.os_name.lower().startswith("win")

    for agent in f.agents:
        label = f"protection: {agent}"
        key = agent.replace(" ", "_")
        if is_win:
            ps_suffix = "; PowerShell commands are judged by text rules only"
            if f.mount_running is True:
                status = "ok"
                detail = f"covered by the demo_cli filesystem mount{ps_suffix}"
            else:
                status = "warn"
                detail = (
                    "NOT covered: the filesystem mount is not running "
                    f"(run demo_cli setup / mount), {fallback}{ps_suffix}"
                )
        else:
            if key == "claude_code":
                if f.syscall_guard:
                    status = "ok"
                    detail = (
                        "runs under the syscall guard "
                        "(each destroyed file backed up at the moment of destruction)"
                    )
                else:
                    status = "warn"
                    detail = f"cannot be supervised: {fallback}"
            elif key == "codex":
                status = "warn"
                detail = (
                    "Codex's hook can only deny, so it cannot be supervised: "
                    f"{fallback}"
                )
            else:
                status = "warn"
                detail = f"cannot be supervised: {fallback}"
        out.append((status, label, detail))

    out.append(
        ("ok", "remote changes", "stopped for review when they can lose data or cannot be recalled; additions are allowed and listed")
    )
    return out


def gather(cfg) -> Facts:
    """The ONE function allowed to do I/O: inspects system and configuration."""
    import os
    from . import checkpoint, syscall_guard
    from .doctor import _host_hook_status

    agents = tuple(
        label.replace(" ", "_")
        for label, path in _host_hook_status(cfg)
        if path is not None
    )

    mount_running = None
    if os.name == "nt":
        from . import guard, mountstate
        st = mountstate.status(cfg)
        mount_running = bool(
            st.running and st.mountpoint and guard._mount_covers_project(st.mountpoint, cfg.project_root)
        )

    return Facts(
        os_name=os.name,
        agents=agents,
        syscall_guard=syscall_guard.available(),
        mount_running=mount_running,
        checkpoint_enabled=checkpoint.enabled(cfg),
    )

