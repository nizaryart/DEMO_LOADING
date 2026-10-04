"""The engine's judgement of an Impact, used by the guard's engine path
and recorded as the prediction.

Order (agreed 2026-09-27; extended C1 review and C2 rulings, 2026-09-28):
  1. demo_cli's own files touched by ANY change - creation and append
     included, as Part A1 decides today      -> ESCALATE
  2. a remote surface whose KIND the policy below escalates -> ESCALATE
  3. a KNOWN destroy nothing can capture: outside the project, of its root,
     or a database write with no capture path -> ESCALATE, even beside an
     unknown: the filesystem layer covers the project folder only
  4. a local effect we cannot resolve        -> DEFER  (to the filesystem
     layer, an ASK, or a stop - decided in D, per layer and host)
  5. nothing pre-existing is destroyed       -> ALLOW (remote changes the
     policy allows are listed in the reason)
  6. everything destroyed exists, lies inside the project and is not the
     root, plus capturable databases         -> REVERSIBLE, ONE set
  7. otherwise                               -> ESCALATE
Sizes are not measured here: nothing is walked.
"""
from __future__ import annotations

import os
from typing import Dict, List, Optional, Tuple

from ..config import control_plane_paths
from ..policy import ALLOW, ESCALATE, REMOTE_POLICY, remote_decision
from ..recovery import _contains, within_project
from .effects import Impact

REVERSIBLE = "REVERSIBLE"
DEFER = "DEFER"


def _related(a: str, b: str) -> bool:
    a, b = os.path.normcase(a), os.path.normcase(b)
    return _contains(a, b) or _contains(b, a)


class Assessment:
    __slots__ = ("plane_hits", "remote_escalated", "outside", "no_capture",
                 "unknown", "capturable")

    def __init__(self, plane_hits: List[str], remote_escalated: List[Tuple[str, str]],
                 outside: List[str], no_capture: Dict, unknown: List,
                 capturable: bool):
        self.plane_hits = plane_hits
        self.remote_escalated = remote_escalated
        self.outside = outside
        self.no_capture = no_capture
        self.unknown = unknown
        self.capturable = capturable


def assess(impact: Impact, cfg) -> Assessment:
    root = os.path.abspath(cfg.project_root or os.getcwd())
    planes = control_plane_paths(cfg)
    real_planes = [os.path.realpath(q) for q in planes]
    hits = sorted(p for p in impact.touched
                  if any(_related(p, q) for q in planes)
                  or any(_related(os.path.realpath(p), q) for q in real_planes))

    remote_escalated = sorted(
        (k, kind) for k, kind in impact.remote.items()
        if remote_decision(kind) == ESCALATE
    )

    outside = [p for p in impact.destroys if not within_project(p, root)]

    capturable = (
        all(os.path.lexists(p) and within_project(p, root) for p in impact.destroys)
        and not remote_escalated
        and not impact.no_capture
    )

    return Assessment(
        plane_hits=hits,
        remote_escalated=remote_escalated,
        outside=outside,
        no_capture=impact.no_capture,
        unknown=impact.unknown,
        capturable=capturable,
    )


def verdict(impact: Impact, cfg) -> Tuple[str, str]:
    a = assess(impact, cfg)
    if a.plane_hits:
        return ESCALATE, f"changes demo_cli's own files ({len(a.plane_hits)} path(s))"
    if a.remote_escalated:
        kinds = sorted({kind for _k, kind in a.remote_escalated})
        return ESCALATE, (f"reaches {len(a.remote_escalated)} remote surface(s) "
                          f"({', '.join(kinds)})")
    if a.outside:
        return ESCALATE, (f"{len(a.outside)} destroyed path(s) lie outside the project "
                          f"or are its root")
    if a.no_capture:
        return ESCALATE, (f"{len(a.no_capture)} database write(s) with no capture "
                          f"path: {next(iter(a.no_capture.values()))}")
    if a.unknown:
        return DEFER, "; ".join(why for _unit, why in a.unknown[:3])
    listed = (f"; {len(impact.remote)} remote change(s) allowed and listed"
              if impact.remote else "")
    if not impact.destroys and not impact.databases:
        return ALLOW, "nothing that exists is destroyed" + listed
    if a.capturable:
        parts = ([f"{len(impact.destroys)} path(s)"] if impact.destroys else []) + \
            ([f"{len(impact.databases)} database(s)"] if impact.databases else [])
        return REVERSIBLE, " and ".join(parts) + " would be captured as one set" + listed
    root = os.path.abspath(cfg.project_root or os.getcwd())
    bad = [p for p in impact.destroys
           if not (os.path.lexists(p) and within_project(p, root))]
    return ESCALATE, (f"{len(bad)} destroyed path(s) lie outside the project "
                      f"or are its root")
