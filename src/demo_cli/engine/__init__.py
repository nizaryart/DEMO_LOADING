"""The engine: understand a command the new way, simulate its effects,
and judge them.

    parse (model.py) -> Invocation -> rules -> effects -> simulate -> Impact
                     -> decision

The engine decides on the guard's engine path (M2.1); the prediction in the
receipt is the same judgement, recorded. DEMO_CLI_SHADOW_ENGINE=0 turns it off.
"""
from __future__ import annotations

import os
import time
from typing import Optional, Tuple

ENGINE = "shadow-1"
BUDGET_MS = 10.0
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
            explicit_db: Optional[str] = None, db_url: Optional[str] = None) -> Prediction:
    """POSIX only. Raises on a bug or on the budget; predict_safely does not.
    `explicit_db` / `db_url`: the check door's --db / --db-url (C2a, Q3) -
    the database a bare SQL line runs against."""
    from .rules import RULES
    from .simulate import simulate
    from .verdict import verdict
    impact = simulate(command, rules or RULES, cwd=cwd,
                      budget_ms=BUDGET_MS if budget_ms is None else budget_ms,
                      sql_target=(explicit_db, db_url))
    decision, why = verdict(impact, cfg)
    return Prediction(impact, decision, why)


def predict_safely(command: str, dialect: str, cfg, explicit_db: Optional[str] = None,
                   db_url: Optional[str] = None) -> Optional[dict]:
    """The receipt's `prediction` field. Never raises."""
    if not enabled():
        return None
    t0 = time.perf_counter()
    try:
        if dialect != "posix":
            out = {"engine": ENGINE, "skipped": dialect}      # PowerShell arrives in C
        else:
            out = _render(predict(command, cfg, explicit_db=explicit_db, db_url=db_url), cfg)
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
    return {"engine": ENGINE, "decision": p.decision, "why": p.why, **lists,
            "truncated": truncated}
