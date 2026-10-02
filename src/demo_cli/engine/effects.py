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

A remote surface carries a KIND (review C2, ruling Q1): what happens there.
verdict.REMOTE_POLICY turns a kind into a verdict; the tool tables only say
what happens.
  DELETE        removed
  OVERWRITE     replaced, or MAY be replaced (apply, set, a database write)
  CREATE        only added
  SEND          outward and unrecallable (publish, a message, a payment)
  SERVICE_LOSS  availability lost (stop, disable, scale to 0, reboot)
  SERVICE_KEEP  availability kept or restored (start, restart, enable)
  RUN           code runs there, unread
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
MKDIR = "MKDIR"          # a template kind: create a directory (-p: and its parents)
SEND = "SEND"
SERVICE_LOSS = "SERVICE_LOSS"
SERVICE_KEEP = "SERVICE_KEEP"

# May-semantics (ruling Q1): the same surface reached twice keeps the kind
# that loses the most.
_LOSS_ORDER = (DELETE, OVERWRITE, SEND, RUN, SERVICE_LOSS, SERVICE_KEEP, CREATE)


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
                 "touched", "remote", "unknown", "uncovered", "within", "databases",
                 "no_capture", "db_urls")

    def __init__(self) -> None:
        self.destroys: Dict[str, str] = {}
        self.destroyed_dirs: Set[str] = set()
        self.created: List[str] = []
        self.creates: Set[str] = set()
        self.changes: Set[str] = set()
        self.touched: Set[str] = set()
        self.remote: Dict[str, str] = {}    # surface label -> kind (C2)
        self.unknown: List[Tuple[str, str]] = []
        self.uncovered: List[str] = []
        self.within: Set[str] = set()     # directories captured whole (WITHIN)
        # Databases (C2a). A sqlite database is a FILE and lives in destroys.
        # `databases`: a capturable local database written (joins the set);
        # `no_capture`: a database written that nothing can capture.
        self.databases: Dict[str, str] = {}   # "db:host/name" -> kind
        self.no_capture: Dict[str, str] = {}  # "db:host/name" -> why
        self.db_urls: Dict[str, str] = {}

    def reach(self, label: str, kind: str) -> None:
        """A remote surface is reached; the same one twice keeps the kind
        that loses the most."""
        old = self.remote.get(label)
        if old is None or _LOSS_ORDER.index(kind) < _LOSS_ORDER.index(old):
            self.remote[label] = kind

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
