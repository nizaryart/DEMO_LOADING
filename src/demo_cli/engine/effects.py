"""The effect language: what a command does to the world, in one vocabulary
every door and every layer can share (see the architecture page).

  DELETE    a path is removed                     capture: copy first
  OVERWRITE a path's content is replaced          capture: copy first
  TRUNCATE  a path is emptied                     capture: copy first
  MOVE      content moves src -> dst              capture: dst if it exists
  CREATE    a new path appears                    nothing to capture
  APPEND    content is added to an existing path  nothing destroyed
  REF       a git ref moves                       (C)
  REMOTE    a surface no local copy can restore   (C)
  RUN       code runs                             understood through that code
  UNKNOWN   something happens we cannot resolve   the reason is kept
"""
from __future__ import annotations

from typing import Dict, List, Set, Tuple

DELETE = "DELETE"
OVERWRITE = "OVERWRITE"
TRUNCATE = "TRUNCATE"
MOVE = "MOVE"
CREATE = "CREATE"
APPEND = "APPEND"
REF = "REF"
REMOTE = "REMOTE"
RUN = "RUN"
UNKNOWN = "UNKNOWN"


class Impact:
    """What a whole command line would do, after simulation.

    `destroys` is keyed by the PRE-EXISTING path whose content is lost, not by
    where the loss happens: in `mv a b && rm b` the content destroyed at `b`
    is `a`'s. `touched` is every path changed in any way, creations and
    appends included - the control-plane question. `creates` means MAY exist,
    new, at the end.

    Plain classes throughout the engine, not dataclasses: it is imported on
    every hook call, and building dataclasses cost ~5 ms of an 8 ms import.
    """
    __slots__ = ("destroys", "destroyed_dirs", "created", "creates", "changes",
                 "touched", "remote", "unknown", "uncovered")

    def __init__(self) -> None:
        self.destroys: Dict[str, str] = {}
        self.destroyed_dirs: Set[str] = set()
        self.created: List[str] = []
        self.creates: Set[str] = set()
        self.changes: Set[str] = set()
        self.touched: Set[str] = set()
        self.remote: Set[str] = set()
        self.unknown: List[Tuple[str, str]] = []
        self.uncovered: List[str] = []

    def destroy(self, path: str, how: str, is_dir: bool = False) -> None:
        self.destroys.setdefault(path, how)
        if is_dir:
            self.destroyed_dirs.add(path)

    def not_understood(self, unit: str, why: str) -> None:
        item = (unit, why)
        if item not in self.unknown:
            self.unknown.append(item)

    def not_covered(self, tool: str) -> None:
        if tool not in self.uncovered:
            self.uncovered.append(tool)
