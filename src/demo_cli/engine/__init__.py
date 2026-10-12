"""The engine: understand a command the new way, simulate its effects,
and judge them.

    POSIX:      parse (model.py)    -> Invocation -> rules -> effects
    PowerShell: parse (ps_model.py) -> binder (ps_bind.py) -> effects   (C3)
                both                -> simulate -> Impact -> decision

The two front ends meet at the same World: one simulation, one verdict.

The engine decides on the guard's engine path (M2.1); the prediction in the
receipt is the same judgement, recorded. DEMO_CLI_SHADOW_ENGINE=0 turns it off.
"""
from __future__ import annotations

import os
import time
from typing import Optional, Tuple

ENGINE = "shadow-1"
BUDGET_MS = 10.0
RETRY_BUDGET_MS = 50.0
KILL_SWITCH = "DEMO_CLI_SHADOW_ENGINE"
_CAP = 20


class Prediction:
    __slots__ = ("impact", "decision", "why")

    def __init__(self, impact, decision: str, why: str):
        self.impact, self.decision, self.why = impact, decision, why


def enabled() -> bool:
    return os.environ.get(KILL_SWITCH, "1").strip() != "0"


def predict(command: str, cfg, rules: Optional[Tuple] = None,
            budget_ms: Optional[float] = None, cwd: Optional[str] = None,
            explicit_db: Optional[str] = None, db_url: Optional[str] = None,
            dialect: str = "posix") -> Prediction:
    """Raises on a bug or on the budget; predict_safely does not.
    `explicit_db` / `db_url`: the check door's --db / --db-url (C2a, Q3) -
    the database a bare SQL line runs against. `dialect` picks the front end
    that READS the line (C3): POSIX or PowerShell. Everything after the
    reading - simulation, effects, verdict - is shared."""
    from .rules import RULES
    from .simulate import simulate
    from .verdict import verdict
    impact = simulate(command, rules or RULES, cwd=cwd, root=cfg.project_root,
                      budget_ms=BUDGET_MS if budget_ms is None else budget_ms,
                      sql_target=(explicit_db, db_url), dialect=dialect)
    decision, why = verdict(impact, cfg)
    return Prediction(impact, decision, why)


def predict_safely(command: str, dialect: str, cfg, explicit_db: Optional[str] = None,
                   db_url: Optional[str] = None) -> Optional[dict]:
    """The receipt's `prediction` field. Never raises."""
    if not enabled():
        return None
    t0 = time.perf_counter()
    try:
        out = _render(predict(command, cfg, explicit_db=explicit_db, db_url=db_url,
                              dialect=dialect), cfg)
    except Exception as exc:
        from .simulate import BudgetExceeded
        why = "budget" if isinstance(exc, BudgetExceeded) else f"{type(exc).__name__}: {exc}"
        out = {"engine": ENGINE, "error": why}
    out["ms"] = round((time.perf_counter() - t0) * 1000, 2)
    return out


def _render(p: Prediction, cfg) -> dict:
    root = os.path.abspath(cfg.project_root or os.getcwd())
    imp = p.impact

    def rel(path: str, is_dir: bool = False) -> str:
        from ..recovery import _contains
        shown = os.path.relpath(path, root) if _contains(root, path) else path
        return shown + ("/" if is_dir and not shown.endswith(os.sep) else "")

    destroys = sorted(imp.destroys.items())
    lists = {
        "destroys": {rel(k, k in imp.destroyed_dirs): v for k, v in destroys[:_CAP]},
        "creates": [rel(x) for x in sorted(imp.creates)[:_CAP]],
        "changes": [rel(x) for x in sorted(imp.changes)[:_CAP]],
        "remote": dict(sorted(imp.remote.items())[:_CAP]),          # label -> kind (2.2)
        "databases": dict(sorted(imp.databases.items())[:_CAP]),
        "no_capture": dict(sorted(imp.no_capture.items())[:_CAP]),
        "unknown": [[u[:120], w] for u, w in imp.unknown[:10]],
        "uncovered": imp.uncovered[:_CAP],
        "within": [rel(x, True) for x in sorted(imp.within)[:_CAP]],
    }
    truncated = (len(destroys) > _CAP or len(imp.creates) > _CAP or len(imp.changes) > _CAP
                 or len(imp.unknown) > 10 or len(imp.uncovered) > _CAP
                 or len(imp.remote) > _CAP or len(imp.databases) > _CAP
                 or len(imp.no_capture) > _CAP)
    out = {"engine": ENGINE, "decision": p.decision, "why": p.why, **lists,
           "truncated": truncated}
    if imp.computed:
        out["computed"] = [[t[:120], o[:200]] for t, o in imp.computed[:10]]
    return out


def combine_guessed(ps_impact, posix_impact):
    """PS8 (Nizar, 2026-10-11): one line, read in BOTH dialects, because the
    door could not say which shell runs it (Codex on Windows sends the tool
    name "Bash" while running PowerShell - V24).

    The tool's own rule decides how the two readings combine: the unknown is
    not safe, and here the unknown is the SHELL. So:
      * whatever either reading destroys is captured - a superset, which is
        what keeps a REVERSIBLE earned;
      * a remote surface either reading reaches is reached;
      * what either reading cannot read stays unread - EXCEPT a PowerShell
        binding error, which means PowerShell itself would refuse to run the
        line, so the POSIX reading is the one that matters;
      * a word the POSIX reading does not know but PowerShell resolves as a
        cmdlet (`Remove-Item`) is not "uncovered": in a POSIX shell it would
        be "command not found" and do nothing.
    One engine, two inputs we cannot tell apart - not two logics.
    """
    from .effects import Impact
    from .ps_bind import resolve
    out = Impact()
    for imp in (ps_impact, posix_impact):
        for path, how in imp.destroys.items():
            out.destroy(path, how, path in imp.destroyed_dirs)
        for c in imp.created:
            if c not in out.created:
                out.created.append(c)
        out.creates |= imp.creates
        out.changes |= imp.changes
        out.touched |= imp.touched
        out.within |= imp.within
        for label, kind in imp.remote.items():
            out.reach(label, kind)
        out.databases.update(imp.databases)
        out.no_capture.update(imp.no_capture)
        out.db_urls.update(imp.db_urls)
        out.computed.extend(imp.computed)
    refused = set(ps_impact.refused)
    for item in ps_impact.unknown:
        if item not in refused:
            out.not_understood(*item)
    for item in posix_impact.unknown:
        out.not_understood(*item)
    for word in ps_impact.uncovered:
        out.not_covered(word)
    for word in posix_impact.uncovered:
        if resolve(word.split()[0]) is None:
            out.not_covered(word)
    out.refused = list(ps_impact.refused)
    return out
