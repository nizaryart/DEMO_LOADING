"""The would-be decision from an Impact. Computed and recorded, never used.

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
from typing import Tuple

from ..config import control_plane_paths
from ..recovery import _contains, within_project
from .effects import (CREATE, DELETE, OVERWRITE, RUN, SEND, SERVICE_KEEP,
                      SERVICE_LOSS, Impact)

ALLOW = "ALLOW"
REVERSIBLE = "REVERSIBLE"
ESCALATE = "ESCALATE"
DEFER = "DEFER"

# Ruling Q1 (C2 review): what a remote change of each kind gets. One table,
# so D can retune it without touching the tool tables. The same rule as the
# local side: a change no local copy restores escalates; adding without loss
# is allowed, and listed.
REMOTE_POLICY = {
    DELETE: ESCALATE,
    OVERWRITE: ESCALATE,
    SEND: ESCALATE,
    RUN: ESCALATE,
    SERVICE_LOSS: ESCALATE,
    SERVICE_KEEP: ALLOW,
    CREATE: ALLOW,
}


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
    escalated = sorted(k for k, kind in impact.remote.items()
                       if REMOTE_POLICY.get(kind, ESCALATE) == ESCALATE)
    if escalated:
        kinds = sorted({impact.remote[k] for k in escalated})
        return ESCALATE, (f"reaches {len(escalated)} remote surface(s) "
                          f"({', '.join(kinds)})")
    outside = [p for p in impact.destroys if not within_project(p, root)]
    if outside:
        return ESCALATE, (f"{len(outside)} destroyed path(s) lie outside the project "
                          f"or are its root")
    if impact.no_capture:
        return ESCALATE, (f"{len(impact.no_capture)} database write(s) with no capture "
                          f"path: {next(iter(impact.no_capture.values()))}")
    if impact.unknown:
        return DEFER, "; ".join(why for _unit, why in impact.unknown[:3])
    listed = (f"; {len(impact.remote)} remote change(s) allowed and listed"
              if impact.remote else "")
    if not impact.destroys and not impact.databases:
        return ALLOW, "nothing that exists is destroyed" + listed
    bad = [p for p in impact.destroys
           if not (os.path.lexists(p) and within_project(p, root))]
    if not bad:
        parts = ([f"{len(impact.destroys)} path(s)"] if impact.destroys else []) + \
            ([f"{len(impact.databases)} database(s)"] if impact.databases else [])
        return REVERSIBLE, " and ".join(parts) + " would be captured as one set" + listed
    return ESCALATE, (f"{len(bad)} destroyed path(s) lie outside the project "
                      f"or are its root")
