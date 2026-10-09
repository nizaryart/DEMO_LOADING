"""Claude Code PreToolUse integration - the auto-fire path.

Claude Code runs a PreToolUse hook *before* a tool executes and passes the tool
call as JSON on stdin:

    {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": "...",
     "tool_input": {"command": "...", "description": "..."}, ...}

A hook steers Claude Code by printing JSON on stdout:

    {"hookSpecificOutput": {"hookEventName": "PreToolUse",
        "permissionDecision": "allow" | "deny" | "ask",
        "permissionDecisionReason": "..."}}

Mapping:
    shadow mode  -> never interferes: evaluate, snapshot, record a receipt,
                    then exit 0 so the normal permission flow is unchanged.
    enforce mode -> ESCALATE => deny, CONTEXT_MISMATCH => ask, otherwise allow
                    (recoverable mutations are snapshotted first, then allowed).
                    An ESCALATE a person may approve (decision.approvable, the
                    ask channel) => ask, but only in ASK_MODES.

Posture: a *decision* is fail-closed (no recovery path on prod => escalate),
but our *own* errors are fail-open - a bug in this tool must never brick the
user's agent. If we cannot parse or evaluate, we step aside (exit 0).
"""
from __future__ import annotations

import json
import os
import sys
from typing import Dict, List, Optional

from . import attributed
from .. import fsreport
from ..classify import POSIX, POWERSHELL
from ..config import load_config
from ..context import Intent
from ..guard import AgentDirectoryUnreachable, Guard, agent_directory
from . import event_list, hook_timeout, load_host_config, reconcile_handler

_FILE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
# Claude Code fires the same PreToolUse shape for both a POSIX shell (Bash) and
# a Windows one (PowerShell); tool_input.command carries the raw command line
# either way, so both route through the same command evaluation path.
_SHELL_TOOLS = {"Bash", "PowerShell"}

_BANNER = "\u2500" * 4

def _stderr(msg: str) -> None:
    sys.stderr.write(msg + "\n")

def _loud_save(result) -> None:
    """Unmissable stderr for a captured recovery point (enforce path)."""
    rid = result.recovery_entry.get("id", "")
    n = len(getattr(result, "affected_paths", None) or []) or None
    what = f"{n} files" if n else "target"
    _stderr("")
    _stderr(f"demo_cli \u2705 recovery point {rid} captured before this ran ({what}).")
    _stderr(f"         mistake? undo it with:  demo_cli undo {rid}")
    try:
        from ..render import feedback_url_for
        url = feedback_url_for(result)
        if url:
            _stderr(f"         wrong call?  report it (prefilled): {url}")
    except Exception:
        pass
    _stderr("")

def _loud_block(result) -> None:
    """Unmissable stderr for an escalate/block (enforce path)."""
    _stderr("")
    _stderr(f"demo_cli \u26d4 blocked: {result.decision.reason}")
    entry = getattr(result, "recovery_entry", None)
    if entry:
        # Captured-then-refused. The snapshot is real; the command is not.
        _stderr(f"         a recovery point ({entry.get('id', '')}) was captured before the")
        _stderr("         refusal; the command did not run, so there is nothing to undo.")
    else:
        _stderr("         nothing was captured, and nothing is claimed to be.")
    try:
        from ..render import feedback_url_for
        url = feedback_url_for(result)
        if url:
            _stderr(f"         wrong call?  report it (prefilled): {url}")
    except Exception:
        pass
    _stderr("")


# The permission modes in which Claude Code SHOWS a hook's "ask" to a person.
# Docs (2026-10-07): Manual (sent as "default"), acceptEdits and plan prompt;
# auto mode does too - "the classifier can still deny the tool call, but it
# can't approve the call silently" (v2.1.211). dontAsk auto-denies anything
# that would prompt; bypassPermissions "disables permission prompts" and the
# docs do not say a hook's ask survives it. Outside this set - and when the
# mode is missing - an approvable escalation is DENIED: an "ask" that nobody
# is shown must never turn into "it ran".
ASK_MODES = frozenset({"default", "acceptEdits", "plan", "auto"})


def escalation_permission(decision, permission_mode: Optional[str]) -> str:
    """deny or ask, for an ESCALATE."""
    return "ask" if decision.approvable and permission_mode in ASK_MODES else "deny"


def _loud_ask(result) -> None:
    """The ask channel's stderr: what the person is being asked to approve."""
    _stderr("")
    _stderr(f"demo_cli \u2753 needs your approval: {result.decision.reason}")
    _stderr("         nothing was captured: if you approve, demo_cli cannot undo it.")
    _stderr("")


def _emit(stdout, permission: Optional[str] = None, reason: Optional[str] = None, *,
          updated_input: Optional[dict] = None,
          notice: Optional[str] = None,
          system_message: Optional[str] = None,
          additional_context: Optional[str] = None) -> None:
    if permission is not None:
        hook_output: Dict = {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission,
            # Prefixed at the single exit point, so no caller can
            # forget. See hooks.attributed.
            "permissionDecisionReason": attributed(reason or ""),
        }
        if updated_input is not None:
            hook_output["updatedInput"] = updated_input
        stdout.write(json.dumps({"hookSpecificOutput": hook_output}))
        stdout.flush()
    else:
        hook_output = {
            "hookEventName": "PreToolUse",
        }
        if updated_input is not None:
            hook_output["updatedInput"] = updated_input
        ctx = additional_context if additional_context is not None else notice
        if ctx is not None:
            hook_output["additionalContext"] = attributed(ctx)
        sys_msg = system_message if system_message is not None else notice
        top: Dict = {
            "hookSpecificOutput": hook_output,
        }
        if sys_msg is not None:
            top["systemMessage"] = attributed(sys_msg)
        stdout.write(json.dumps(top))
        stdout.flush()


def run_pretooluse(stdin, stdout) -> int:
    # Fail-open on our own parsing errors: never brick the agent. But fail-open
    # LOUD - surface it on stderr so the user can see the tool stepped aside
    # rather than silently allowing.
    try:
        raw = stdin.read()
        data = json.loads(raw) if raw.strip() else {}
    except Exception as exc:
        sys.stderr.write(f"demo_cli: could not parse hook input, stepping aside ({exc})\n")
        return 0

    tool_name = data.get("tool_name")
    tool_input = data.get("tool_input") or {}
    cwd = data.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    description = tool_input.get("description")

    is_shell = tool_name in _SHELL_TOOLS
    is_file = tool_name in _FILE_TOOLS
    if not (is_shell or is_file):
        # Beta scope: gate shell + file-write tools. Everything else passes.
        return 0

    guard = None
    try:
        cfg = load_config(start=cwd)
        # WHAT THE FILESYSTEM LAYER DID, BEFORE ANYTHING ELSE.
        #
        # It runs in another process, does not block, and logs to a file
        # inside the Administrators-only backing directory - so the agent
        # cannot see it work, and on 2026-09-02 one reported four snapshotted
        # deletions as "unblocked destructions". Reported here because this is
        # the only channel that reaches the agent. One command behind by
        # nature: PreToolUse fires before the command runs, so these belong to
        # the PREVIOUS one, and the wording says so.
        fs_note = fsreport.summary(cfg)
        if fs_note:
            _stderr("")
            _stderr(fs_note)
        guard = Guard(config=cfg)
        if is_shell:
            command = (tool_input.get("command") or "").strip()
            if not command:
                return 0
            # Claude Code fires the same event shape for both shells, and the
            # tool name is the only reliable signal of which one wrote the text.
            # A Windows box can run either, so os.name is NOT a safe guess.
            with agent_directory(cwd):
                result = guard.evaluate(
                    command,
                    intent=Intent(reasoning=description),
                    agent_id=data.get("agent_id", "claude-code"),
                    session_id=data.get("session_id", "unknown"),
                    dialect=POWERSHELL if tool_name == "PowerShell" else POSIX,
                    door="agent",
                    can_supervise=(tool_name == "Bash"),
                )
        else:
            # Edit / Write / MultiEdit -> file_path ; NotebookEdit -> notebook_path
            file_path = tool_input.get("file_path") or tool_input.get("notebook_path")
            if not file_path:
                return 0
            # BOTH ENTRY POINTS. evaluate_file_edit does its own
            # os.path.abspath(file_path), so wrapping only the shell call
            # above would leave every relative Edit / Write / MultiEdit /
            # NotebookEdit resolving against the hook's directory.
            with agent_directory(cwd):
                result = guard.evaluate_file_edit(
                    file_path, tool_name=tool_name,
                    intent=Intent(reasoning=description),
                    agent_id=data.get("agent_id", "claude-code"),
                    session_id=data.get("session_id", "unknown"),
                )
    except AgentDirectoryUnreachable as exc:
        # We cannot stand where the agent stands, so a relative path in this
        # call cannot be resolved and nothing can be captured for it. Codex has
        # denied here since 09-13; this host fell into the blanket handler below
        # and stepped aside on the identical exception.
        if getattr(guard, "mode", None) != "enforce":
            _stderr(f"demo_cli [shadow] would deny: the directory the agent "
                    f"reported ({exc}) cannot be entered")
            return 0
        _emit(stdout, "deny",
              f"the working directory the agent reported ({exc}) cannot be "
              f"entered, so a relative path in this call cannot be resolved "
              f"and nothing can be captured for it")
        return 0
    except Exception as exc:  # our bug must not block the user
        sys.stderr.write(f"demo_cli: internal error, stepping aside ({exc})\n")
        return 0

    updated = None
    sys_msg = None
    add_ctx = None
    if result.decision.decision == "SUPERVISED":
        if result.rewrite:
            updated = dict(tool_input)
            updated["command"] = result.rewrite
            orig_disp = command if len(command) <= 200 else command[:200] + "…"
            sys_msg = (
                "demo_cli will run this under the syscall guard, "
                f"so each file it destroys inside the project is backed up first: {orig_disp}"
            )
            gid = result.group_id or ""
            add_ctx = (
                f"this command was rewritten by demo_cli and runs as: {result.rewrite}. "
                f"Each file it destroys inside the project is backed up at the moment of "
                f"destruction (outside it each destroyed file is recorded, not backed up); "
                f"undo with `demo_cli undo {gid}`."
            )
        else:
            sys_msg = result.decision.reason
            add_ctx = result.decision.reason

    # shadow mode: observe only - but make a genuinely interesting decision or a
    # fresh snapshot *visible* on stderr, so value isn't silently buried.
    if guard.mode != "enforce":
        if result.decision.decision == "SUPERVISED":
            sys.stderr.write(f"demo_cli [shadow] SUPERVISED: {result.decision.reason}\n")
            if updated:
                _emit(stdout, updated_input=updated, system_message=sys_msg, additional_context=add_ctx)
                return 0
        elif result.decision.is_blocking or result.decision.is_ask:
            sys.stderr.write(f"demo_cli [shadow] {result.decision.decision}: {result.decision.reason}\n")
        elif result.recovery_entry:
            rp = os.path.basename(result.recovery_entry["recovery_point"])
            rid = result.recovery_entry.get("id", "")
            sys.stderr.write(f"demo_cli [shadow] snapshot {rid} captured ({rp}); undo with `demo_cli undo {rid}`\n")
        return 0

    reason = result.decision.reason
    if result.decision.decision == "SUPERVISED":
        _stderr("")
        _stderr(f"demo_cli \u2705 {reason}")
        _stderr("")
        _emit(stdout, updated_input=updated, system_message=sys_msg, additional_context=add_ctx)
        return 0

    # Blocking is tested FIRST. The nonrecoverable-surface branch captures and
    # then refuses, so the save arm would announce a recovery point for a
    # command that never ran. The shadow block above already orders it this way.
    if result.decision.is_blocking:
        if escalation_permission(result.decision, data.get("permission_mode")) == "ask":
            _loud_ask(result)
            reason += ("\n\nApprove only if this is intended: nothing was captured, "
                       "so demo_cli cannot undo it.")
            if result.decision.surface:
                from .. import policy
                reason += (f" If it has to come back: "
                           f"{policy.recovery_hint(result.decision.surface)}.")
            if fs_note:
                reason += "\n\n" + fs_note
            _emit(stdout, "ask", reason)
            return 0
        _loud_block(result)         # <-- make the block legible, with report link
        if fs_note:
            reason += "\n\n" + fs_note
        _emit(stdout, "deny", reason)
        return 0

    if result.decision.is_ask:
        if fs_note:
            reason += "\n\n" + fs_note
        _emit(stdout, "ask", reason)
        return 0

    has_capture = bool(result.recovery_entry or result.decision.decision in ("REVERSIBLE", "DRY_RUN"))
    if has_capture:
        if result.recovery_entry:
            rid = result.recovery_entry.get("id", "")
            reason += f"  (recovery point {rid}; undo with `demo_cli undo {rid}`)"
            _loud_save(result)          # <-- make the save FELT, on stderr
        if fs_note:
            reason += "\n\n" + fs_note
        _emit(stdout, notice=reason)
        return 0

    if fs_note:
        _emit(stdout, notice=fs_note)
        return 0

    return 0


# --------------------------------------------------------------------------
# Installation helpers
# --------------------------------------------------------------------------

_FILE_MATCHER = "Edit|Write|MultiEdit|NotebookEdit"
# Separate matcher entries (rather than one "Bash|PowerShell" block) so an
# older Bash-only install upgrades by gaining a new PowerShell block, and so
# `"Bash" in matchers` stays a valid way to check coverage.
_SHELL_MATCHERS = ("Bash", "PowerShell")


# DECLARED, not left to the host, and the value is hooks.hook_timeout() so
# both hosts read one knob. We used to declare none here and take whatever
# Claude Code's default is - a number we do not know and therefore cannot
# size the snapshot cap against.
def _handler() -> Dict:
    return {"type": "command", "command": "demo_cli hook",
            "timeout": hook_timeout()}


def settings_snippet() -> Dict:
    return {
        "hooks": {
            "PreToolUse": [
                {"matcher": m, "hooks": [_handler()]} for m in _SHELL_MATCHERS
            ] + [
                {"matcher": _FILE_MATCHER, "hooks": [_handler()]},
            ]
        }
    }


def install_into_settings(path: str) -> List[str]:
    """Register or RECONCILE the PreToolUse hooks. Returns what changed.

    Add-if-absent until 2026-09-17: a matching command string skipped the
    whole entry, so the raised timeout never reached an existing install and
    doctor reported it green. Now each matcher is brought up to _handler().
    """
    settings = load_host_config(path)
    pre = event_list(settings, "PreToolUse")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def _alternatives(matcher) -> set:
        """A Claude Code matcher is a `|`-separated set of tool names."""
        return {p.strip() for p in str(matcher or "").split("|") if p.strip()}

    def _ours(matcher: str):
        """Our handler for `matcher`, in any block that covers it.

        Compared by alternative, not whole string: a block matching
        "Bash|PowerShell" equals neither "Bash" nor "PowerShell", so the
        installer appended a second block for each and the hook fired twice
        per command.
        """
        want = _alternatives(matcher)
        for b in pre:
            if not isinstance(b, dict):
                continue
            if not (want & _alternatives(b.get("matcher"))):
                continue
            for h in b.get("hooks") or []:
                if isinstance(h, dict) and h.get("command") == "demo_cli hook":
                    return h
        return None

    # A pre-PowerShell install is still upgraded by appending the missing
    # block; what is new is that the block already there is no longer skipped.
    changed: List[str] = []
    for matcher in (*_SHELL_MATCHERS, _FILE_MATCHER):
        handler = _ours(matcher)
        if handler is None:
            pre.append({"matcher": matcher, "hooks": [_handler()]})
            changed.append(f"{matcher}: registered")
        else:
            changed += [f"{matcher}: {c}" for c in
                        reconcile_handler(handler, _handler())]

    with open(path, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")
    return changed
