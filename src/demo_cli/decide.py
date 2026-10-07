"""The decision function.

Pure and fail-closed. It is the single place that turns a description of a
command (classification + context + whether a recovery point was actually
captured) into a disposition. It never performs IO and never captures
anything itself, which is exactly why it cannot lie: `recovery_captured` is
supplied by the orchestrator only when a snapshot of the *real* target
succeeded. There is no default target to fall back to.

Invariant:
    a mutating action must be recoverable AND match its declared context,
    otherwise escalate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .classify import Classification
from . import policy

# Dispositions
ALLOW = "ALLOW"
DRY_RUN = "DRY_RUN"
REVERSIBLE = "REVERSIBLE"
SUPERVISED = "SUPERVISED"
CONTEXT_MISMATCH = "CONTEXT_MISMATCH"
ESCALATE = "ESCALATE"

# Dispositions that mean "do not let this proceed unattended".
BLOCKING = frozenset({ESCALATE})
# Dispositions that warrant surfacing to a human even though a snapshot exists.
ASK = frozenset({CONTEXT_MISMATCH})

# Three human-facing postures. The six dispositions are precise but jargony;
# a reader needs to grasp the stance in one glance. Posture collapses them into
# SAFE (will proceed) / REVIEW (needs a human) / BLOCKED (stopped), and the
# exact disposition stays available as a subtitle.
SAFE = "SAFE"
REVIEW = "REVIEW"
BLOCKED = "BLOCKED"

_POSTURE = {
    ALLOW: SAFE, DRY_RUN: SAFE, REVERSIBLE: SAFE, SUPERVISED: SAFE,
    CONTEXT_MISMATCH: REVIEW,
    ESCALATE: BLOCKED,
}


def posture(disposition: str) -> str:
    """Collapse a disposition into one of SAFE / REVIEW / BLOCKED."""
    return _POSTURE.get(disposition, REVIEW)

INVARIANT = "mutating_actions_must_be_recoverable_and_match_the_declared_context"



@dataclass
class Decision:
    decision: str
    reason: str
    recoverable: bool = False
    surface: Optional[str] = None
    next_steps: List[str] = field(default_factory=list)
    # The ask channel (policy.ESCALATION_CHANNEL): an ESCALATE a person may
    # approve on the spot. Read only by the doors that can show a person a
    # question; False on every other disposition.
    approvable: bool = False

    @property
    def is_blocking(self) -> bool:
        return self.decision in BLOCKING

    @property
    def is_ask(self) -> bool:
        return self.decision in ASK


def decide(
    c: Classification,
    environment: str,
    recovery_captured: bool,
    mismatches: Optional[List[Tuple[str, str, str]]] = None,
    approval_ok: bool = False,
    preview_count: Optional[int] = None,
    supervisable: bool = False,
    net: Optional[str] = None,
    env_declared: bool = False,
) -> Decision:
    """`env_declared`: `environment` came from a declaration (--actual-env or
    a .demo_cli.toml target), not from a guess over the command's words."""
    mismatches = mismatches or []
    # A target declared production is never approved on the spot: there the
    # structural approval token, or a person outside the agent, decides.
    confirm_env = env_declared and environment in policy.CONFIRM_ENVIRONMENTS

    def asks(channel: bool) -> bool:
        return channel and not confirm_env

    # 1. Opaque remote execution: the payload is unknown until it runs, so it
    #    can be neither previewed nor snapshotted.
    #    1a. Code the engine cannot read, run on a NAMED surface (ssh host cmd,
    #        gh workflow run, redis EVAL ...): the person sees the command, so
    #        it follows that surface's ask channel row (ruling (b), 2026-10-07).
    if c.remote_exec and c.run_surfaces:
        names = ", ".join(c.run_surfaces)
        return Decision(
            ESCALATE,
            f"Runs code demo_cli cannot read, on {names}; nothing it does there can "
            "be captured.",
            recoverable=False,
            surface=c.run_surfaces[0],
            next_steps=[
                "Read what the command runs before approving it.",
                f"If it already ran, restore from the provider: {policy.recovery_hint(c.run_surfaces[0])}.",
            ],
            approvable=asks(all(policy.may_ask(s) for s in c.run_surfaces)),
        )
    #    1b. Fetch-and-run: nobody can see the payload before it runs.
    if c.remote_exec:
        return Decision(
            ESCALATE,
            "Opaque remote execution (fetch-and-run); payload unknown before it runs.",
            recoverable=False,
            next_steps=[
                "Download the script to a file first, review it, then run it.",
                "Or pin and verify a known checksum before executing.",
            ],
            approvable=asks(policy.NO_SURFACE_CHANNEL["remote_exec"] == policy.ASK),
        )

    # 2. Nothing mutating - outside the invariant entirely.
    if not c.needs_recovery:
        return Decision(ALLOW, "Non-mutating action; outside the invariant.", recoverable=False)

    # 3. A surface a local snapshot cannot truthfully cover. Honest escalation:
    #    we do NOT claim recoverability we cannot provide.
    if c.nonrecoverable_surface:
        if approval_ok:
            return Decision(
                ALLOW,
                f"Non-recoverable surface ({c.nonrecoverable_surface}) carried a valid "
                "structural approval the agent could not forge.",
                recoverable=False,
                surface=c.nonrecoverable_surface,
            )
        return Decision(
            ESCALATE,
            f"Mutation of a non-recoverable surface ({c.nonrecoverable_surface}); a local "
            "snapshot cannot cover its blast radius.",
            recoverable=False,
            surface=c.nonrecoverable_surface,
            next_steps=[
                "Confirm the external effect is intended and authorised.",
                "Supply a structural approval token, or perform it outside the agent.",
                f"If it already ran, restore from the provider: {policy.recovery_hint(c.nonrecoverable_surface)}.",
            ],
            approvable=asks(policy.may_ask(c.nonrecoverable_surface)),
        )

    # 4. Valid-but-wrong-context: a reasonable mutation pointed at the wrong place.
    if mismatches:
        if recovery_captured:
            return Decision(
                CONTEXT_MISMATCH,
                "Mutating action did not match the declared context; a recovery point "
                "was captured first and the mismatch is surfaced for review.",
                recoverable=True,
                next_steps=[
                    "Verify the target environment / branch / account is the intended one.",
                    "To declare this target's environment: demo_cli target add <pattern> --env <env>",
                ],
            )
        return Decision(
            ESCALATE,
            "Mutating action did not match the declared context and no recovery point "
            "could be captured.",
            recoverable=False,
            next_steps=[
                "Verify the target environment / branch / account is the intended one.",
                "Provide a snapshot target (--target / --db / --db-url) or back up first.",
                "To declare this target's environment: demo_cli target add <pattern> --env <env>",
            ],
            approvable=asks(policy.NO_SURFACE_CHANNEL["context_mismatch"] == policy.ASK),
        )

    # 4b. A target DECLARED production (never a guess from the command's
    #     words): recoverable or not, a person sees it. CONTEXT_MISMATCH is the
    #     disposition every door already shows a person (Claude Code: ask;
    #     Codex, which has no ask: allowed with the warning in its context).
    if confirm_env and recovery_captured:
        return Decision(
            CONTEXT_MISMATCH,
            f"The target is declared '{environment}'. A recovery point was captured "
            "first; the change is surfaced for a person to confirm.",
            recoverable=True,
            next_steps=[
                "Confirm this change is meant for the declared environment.",
                "Undo restores the recovery point if it was not.",
            ],
        )

    # 5. Recoverable: a recovery point of the real target was captured.
    if recovery_captured:
        if preview_count is not None:
            return Decision(
                DRY_RUN,
                f"Previewed: {preview_count} row(s) would be affected. Recovery point "
                "captured first; reversible.",
                recoverable=True,
            )
        return Decision(
            REVERSIBLE,
            "Recovery point captured before the action; reversible.",
            recoverable=True,
        )

    # 6. Fail-closed: a mutating action with no captured recovery point escalates
    #    in EVERY environment - dev/test/sandbox/staging included. There is no
    #    low-blast exception: an unrecoverable mutation is never waved through on
    #    the strength of an environment label, matching the invariant above.
    #    Never silently allowed.
    if supervisable:
        if net == "mount":
            reason = ("covered by the demo_cli filesystem mount: each file it "
                      "destroys is backed up before modification.")
        else:
            reason = ("covered by the syscall guard: each file it destroys is "
                      "backed up at the moment of destruction.")
        return Decision(
            SUPERVISED,
            reason,
            recoverable=True,
        )

    return Decision(
        ESCALATE,
        f"No recovery path for a {c.matched_rule or 'mutating action'} on "
        f"'{environment}'; cannot auto-recover. Human input required.",
        recoverable=False,
        next_steps=[
            "Add --db / --db-url / --target so a recovery point can be captured.",
            "Or create an independent backup before proceeding.",
            "To declare target recovery policy: demo_cli target add <pattern> --recovery none|snapshot",
        ],
        approvable=asks(policy.NO_SURFACE_CHANNEL["local_no_recovery"] == policy.ASK),
    )
