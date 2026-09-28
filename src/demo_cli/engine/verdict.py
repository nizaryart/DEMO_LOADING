"""The would-be decision from an Impact. Computed and recorded, never used.

Order (agreed 2026-09-27):
  1. demo_cli's own files touched by ANY change - creation and append
     included, as Part A1 decides today      -> ESCALATE
  2. a remote surface                        -> ESCALATE
  3. a KNOWN destroy outside the project, or of its root -> ESCALATE, even
     beside an unknown: the filesystem layer covers the project folder only,
     so deferring cannot save it (review C1, 2026-09-28)
  4. a local effect we cannot resolve        -> DEFER  (to the filesystem
     layer, an ASK, or a stop - decided in D, per layer and host)
  5. nothing pre-existing is destroyed       -> ALLOW
  6. everything destroyed exists, lies inside the project and is not the
     root                                    -> REVERSIBLE, captured as ONE set
  7. otherwise                               -> ESCALATE
Sizes are not measured here: nothing is walked.
"""
from __future__ import annotations

import os
from typing import Tuple

from ..config import control_plane_paths
from ..recovery import _contains, within_project
from .effects import Impact

ALLOW = "ALLOW"
REVERSIBLE = "REVERSIBLE"
ESCALATE = "ESCALATE"
DEFER = "DEFER"


def _related(a: str, b: str) -> bool:
    a, b = os.path.normcase(a), os.path.normcase(b)
    return _contains(a, b) or _contains(b, a)


def verdict(impact: Impact, cfg) -> Tuple[str, str]:
    root = os.path.abspath(cfg.project_root or os.getcwd())
    planes = control_plane_paths(cfg)
    real_planes = [os.path.realpath(q) for q in planes]
    hits = sorted(p for p in impact.touched
                  if any(_related(p, q) for q in planes)
                  or any(_related(os.path.realpath(p), q) for q in real_planes))
    if hits:
        return ESCALATE, f"changes demo_cli's own files ({len(hits)} path(s))"
    if impact.remote:
        return ESCALATE, f"reaches {len(impact.remote)} remote surface(s)"
    outside = [p for p in impact.destroys if not within_project(p, root)]
    if outside:
        return ESCALATE, (f"{len(outside)} destroyed path(s) lie outside the project "
                          f"or are its root")
    if impact.unknown:
        return DEFER, "; ".join(why for _unit, why in impact.unknown[:3])
    if not impact.destroys:
        return ALLOW, "nothing that exists is destroyed"
    bad = [p for p in impact.destroys
           if not (os.path.lexists(p) and within_project(p, root))]
    if not bad:
        return REVERSIBLE, f"{len(impact.destroys)} path(s) would be captured as one set"
    return ESCALATE, (f"{len(bad)} destroyed path(s) lie outside the project "
                      f"or are its root")
