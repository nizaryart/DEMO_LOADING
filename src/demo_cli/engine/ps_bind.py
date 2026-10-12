"""The parameter binder: what PowerShell would bind each word to (C3, PS2).

This is the heart of C3, and the reason a regular expression could never do
this job. PowerShell does not read a command line left to right as text - it
resolves the cmdlet, picks a PARAMETER SET, and binds each word to a
parameter by name, by position, or from the pipeline. Which file a line
touches is the OUTCOME of that binding:

    Set-Content a.txt hi          a.txt -> -Path (position 0), hi -> -Value
    Remove-Item -Rec d            -Rec is the shortest unambiguous prefix of
                                  -Recurse, so the delete is recursive
    "a.txt" | Remove-Item         the pipeline value binds to -Path ByValue
    Remove-Item a.txt -F          AMBIGUOUS (-Filter / -Force): PowerShell
                                  binds nothing and the command does not run

The tables come from the installed PowerShell, never from hand-written lists
(ruling PS2): `tools/c3/dump_bindings.ps1` asks it for every cmdlet's
parameter sets, positions, pipeline inputs, switches and aliases, and
`tools/c3/gen_ps_tables.py` turns that into ps_tables_data.py. A new
PowerShell version is a regeneration, not a code change.

NOTHING IS GUESSED. Any line this module cannot bind the way PowerShell
would - an unknown cmdlet, an unknown or ambiguous parameter, no parameter
set satisfied - comes back with `uncovered` set, and the engine turns that
into "not understood": the runtime net, else a checkpoint, else escalate.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ..ps_model import PsCommand, PsWord
from .ps_tables_data import ALIASES, CMDLETS, COMMON

# The common parameters that take a VALUE; every other common parameter is a
# switch. -WhatIf and -Confirm are switches and carry a ruling of their own
# (PS4: -WhatIf means nothing happens).
_COMMON_WITH_VALUE = {
    "ErrorAction", "WarningAction", "InformationAction", "ErrorVariable",
    "WarningVariable", "InformationVariable", "OutVariable", "OutBuffer",
    "PipelineVariable",
}

# Alias -> cmdlet, lower-cased once. PowerShell matches command names without
# regard to case, and so does `del` / `DEL` / `Del`.
_ALIAS_LC = {k.lower(): v for k, v in ALIASES.items()}
_CMDLET_LC = {k.lower(): k for k in CMDLETS}


def resolve(name: str) -> Optional[str]:
    """The cmdlet a command word means, or None when it is not a cmdlet.

    `rm` -> Remove-Item, `Remove-Item` -> Remove-Item, `python` -> None (a
    native program: PowerShell passes its words through untouched, so there
    is nothing to bind).
    """
    if not name:
        return None
    low = name.lower()
    if low in _CMDLET_LC:
        return _CMDLET_LC[low]
    target = _ALIAS_LC.get(low)
    if target and target.lower() in _CMDLET_LC:
        return _CMDLET_LC[target.lower()]
    return None


class Bound:
    """The result of binding one command.

    `params` maps a CANONICAL parameter name to the words bound to it, so a
    caller asks for "Path" and gets it whether the line said -Path, -LP,
    -LiteralPath or nothing at all (positional). `switches` holds the
    switches that are on. `uncovered` is the reason binding failed, and when
    it is set nothing else may be trusted.
    """
    __slots__ = ("cmdlet", "set_name", "params", "switches", "uncovered", "native")

    def __init__(self, cmdlet: Optional[str], set_name: str = "",
                 params: Optional[Dict[str, List[PsWord]]] = None,
                 switches: Optional[set] = None, uncovered: str = "",
                 native: bool = False) -> None:
        self.cmdlet = cmdlet
        self.set_name = set_name
        self.params: Dict[str, List[PsWord]] = params or {}
        self.switches = switches or set()
        self.uncovered = uncovered
        self.native = native             # not a cmdlet: a program PowerShell runs

    def first(self, *names: str) -> Optional[PsWord]:
        for n in names:
            got = self.params.get(n)
            if got:
                return got[0]
        return None

    def values(self, *names: str) -> List[PsWord]:
        """Every value bound to any of `names`, array literals expanded."""
        out: List[PsWord] = []
        for n in names:
            for w in self.params.get(n, []):
                out.extend(w.values)
        return out

    def has(self, *names: str) -> bool:
        return any(n in self.switches for n in names)

    def __repr__(self) -> str:          # pragma: no cover - debugging only
        return (f"Bound({self.cmdlet!r}, set={self.set_name!r}, "
                f"params={ {k: [w.value for w in v] for k, v in self.params.items()} }, "
                f"switches={sorted(self.switches)}, uncovered={self.uncovered!r})")


def _match_parameter(given: str, names: Dict[str, str]) -> Tuple[Optional[str], str]:
    """Resolve one -Name the way PowerShell does: exact (case-insensitive)
    first, then the shortest unambiguous PREFIX over names and aliases.

    Returns (canonical name, reason). A prefix matching two parameters is an
    error in PowerShell - it binds nothing and the command does not run - so
    it is an error here too, never a guess (VERIFIED: `Remove-Item a.txt -F`
    -> "the parameter name 'F' is ambiguous. Possible matches include:
    -Filter -Force", AG2 A8 case 9_3).
    """
    low = given.lower()
    if low in names:
        return names[low], ""
    hits = sorted({names[k] for k in names if k.startswith(low)})
    if len(hits) == 1:
        return hits[0], ""
    if len(hits) > 1:
        return None, (f"-{given} is ambiguous: it could be "
                      + " or ".join("-" + h for h in hits[:4]))
    return None, f"-{given} is not a parameter of this cmdlet"


def bind(command: PsCommand, piped_value: Optional[PsWord] = None) -> Bound:
    """Bind one parsed command, PowerShell's way.

    `piped_value` is what the previous pipeline element produced, when it is a
    value this engine could read (`"a.txt" | Remove-Item`).
    """
    cmdlet = resolve(command.name)
    if cmdlet is None:
        return Bound(None, native=True)

    supports_whatif, sets = CMDLETS[cmdlet]
    best: Optional[Bound] = None
    reasons: List[str] = []

    for set_name, _is_default, params in sets:
        got = _bind_set(command, set_name, params, piped_value, supports_whatif)
        if not got.uncovered:
            # The first set that accepts every word wins, as PowerShell picks
            # the one set that can be satisfied. Prefer the one that bound
            # more words, so `-LiteralPath x` does not land in the Path set.
            if best is None or len(got.params) > len(best.params):
                best = got
        else:
            reasons.append(got.uncovered)
    if best is not None:
        return best
    # No parameter set accepted the line: say why, once.
    seen: List[str] = []
    for r in reasons:
        if r not in seen:
            seen.append(r)
    return Bound(cmdlet, uncovered="; ".join(seen[:2]) or "no parameter set fits this line")


def _bind_set(command: PsCommand, set_name: str, params, piped_value, supports_whatif) -> Bound:
    """Try one parameter set. Every word must land somewhere, or it fails."""
    by_name: Dict[str, str] = {}
    switches: set = set()
    positional: List[Tuple[int, str]] = []
    pipeline_byvalue: Optional[str] = None
    pipeline_byprop: Optional[str] = None

    for name, position, _mandatory, byvalue, byprop, is_switch, aliases in params:
        by_name[name.lower()] = name
        for a in aliases:
            by_name[a.lower()] = name
        if is_switch:
            switches.add(name)
        if position >= 0:
            positional.append((position, name))
        if byvalue and pipeline_byvalue is None:
            pipeline_byvalue = name
        if byprop and pipeline_byprop is None:
            pipeline_byprop = name
    positional.sort()

    for name in COMMON:
        by_name.setdefault(name.lower(), name)
        if name not in _COMMON_WITH_VALUE:
            switches.add(name)

    bound: Dict[str, List[PsWord]] = {}
    on: set = set()
    operands: List[PsWord] = []
    i = 0
    args = command.args
    while i < len(args):
        w = args[i]
        if not w.is_param:
            operands.append(w)
            i += 1
            continue
        canonical, why = _match_parameter(w.param_name or "", by_name)
        if canonical is None:
            return Bound(None, uncovered=why)
        if canonical in switches:
            # -Force, and -Confirm:$false / -WhatIf:$true.
            attached = w.param_value
            if attached is None or attached.value.lower() not in ("$false", "false", "0"):
                on.add(canonical)
            i += 1
            continue
        if w.param_value is not None:                  # -Name:value
            bound.setdefault(canonical, []).append(w.param_value)
            i += 1
            continue
        if i + 1 < len(args) and not args[i + 1].is_param:
            bound.setdefault(canonical, []).append(args[i + 1])
            i += 2
            continue
        return Bound(None, uncovered=f"-{w.param_name} was given no value")

    # Whatever is left binds by position, in the set's own order.
    free = [name for _p, name in positional if name not in bound]
    for k, w in enumerate(operands):
        if k < len(free):
            bound.setdefault(free[k], []).append(w)
        else:
            return Bound(None, uncovered=(
                f"{command.name} was given more values than its parameters take"))

    # A value arriving through the pipeline binds last: ByValue when the
    # cmdlet takes one, else ByPropertyName (Get-ChildItem | Remove-Item
    # binds the FileInfo's PSPath to -LiteralPath: VERIFIED, A8 case 10_2).
    if piped_value is not None:
        target = pipeline_byvalue or pipeline_byprop
        if target and target not in bound:
            bound.setdefault(target, []).append(piped_value)

    if supports_whatif and "WhatIf" in on:
        pass                                            # PS4: the caller checks it
    return Bound(_CMDLET_LC[command.name.lower()] if command.name.lower() in _CMDLET_LC
                 else resolve(command.name), set_name, bound, on)


def pipeline_target(cmdlet: str, byprop: bool = True) -> Optional[str]:
    """Which parameter a piped object binds to - the one C3 needs to know for
    `Get-ChildItem *.tmp | Remove-Item` (the FileInfo binds ByPropertyName)."""
    entry = CMDLETS.get(cmdlet)
    if not entry:
        return None
    for _set_name, _default, params in entry[1]:
        for name, _pos, _m, byvalue, byp, _sw, _al in params:
            if byvalue or (byprop and byp):
                return name
    return None
