"""Running a PowerShell line on the engine's world (C3).

`ps_model` reads the line, `ps_bind` says what each word binds to, and this
file turns the binding into the SAME effects a POSIX line produces -
world.remove, world.write, world.copy, world.move, world.create - so a
PowerShell delete and a POSIX delete arrive at `decide.py` as the same thing.
There is no second decider, no second policy and no second effect vocabulary;
that is the whole point of calling C3 a front end rather than a guard.

EVERY EFFECT BELOW WAS MEASURED ON POWERSHELL 5.1, NOT READ IN THE DOCS
(the sandbox runs are in the internship notes, 2026-10-10). Four of them
contradict what the documentation suggests, and each one would have been a
wrong answer:

  Copy-Item a.txt b.txt      OVERWRITES an existing b.txt with no -Force.
  Rename-Item a b            REFUSES an existing b EVEN WITH -Force - unlike
                             Move-Item, which -Force does overwrite.
  New-Item a.txt -Force      TRUNCATES an existing a.txt to zero bytes.
  Set-Content                has NEITHER -NoClobber NOR -Append; only
                             Out-File has -NoClobber, only Add-Content and
                             Out-File -Append append.

And two that decide whether a line does anything at all:

  Remove-Item <non-empty dir> without -Recurse asks before it deletes. With
  nobody to answer it fails and deletes nothing - but a person at a prompt
  may say yes, so the engine keeps it as a DELETE (the stricter reading).
  -Include is ignored unless -Path ends with a wildcard, which makes
  `Remove-Item -Path d -Include *.txt` delete nothing. C3 does not model
  -Include / -Exclude / -Filter at all: the line is not understood.
"""
from __future__ import annotations

import base64
import os
import re
from typing import List, Optional, Tuple

from ..ps_model import PsCommand, PsScript, PsWord, parse as ps_parse
from . import ps_bind
from .effects import (CREATE, DELETE, OVERWRITE, SERVICE_KEEP, SERVICE_LOSS,
                      TRUNCATE)

# Cmdlets that reach something that is NOT a file: a service, a process, a
# disk. They go to the same surfaces the POSIX engine uses for systemctl,
# kill and mkfs - one vocabulary, so `Stop-Service x` and `systemctl stop x`
# are judged by the same policy row. Matched by NAME (with their aliases),
# before binding: some live in modules this machine's dump does not cover
# (Storage), and a surface must not depend on which modules were installed.
SURFACES = {
    "stop-service": ("service:scm@local", SERVICE_LOSS),
    "spsv": ("service:scm@local", SERVICE_LOSS),
    "suspend-service": ("service:scm@local", SERVICE_LOSS),
    "start-service": ("service:scm@local", SERVICE_KEEP),
    "sasv": ("service:scm@local", SERVICE_KEEP),
    "resume-service": ("service:scm@local", SERVICE_KEEP),
    "restart-service": ("service:scm@local", SERVICE_KEEP),
    "set-service": ("service:scm@local", OVERWRITE),
    "new-service": ("service:scm@local", CREATE),
    "remove-service": ("service:scm@local", DELETE),
    "stop-process": ("process:local", SERVICE_LOSS),
    "spps": ("process:local", SERVICE_LOSS),
    "stop-computer": ("power:local", SERVICE_LOSS),
    "restart-computer": ("power:local", SERVICE_LOSS),
    "format-volume": ("device:volume", DELETE),
    "clear-disk": ("device:disk", DELETE),
    "remove-partition": ("device:disk", DELETE),
    "initialize-disk": ("device:disk", DELETE),
    "clear-recyclebin": ("device:recyclebin", DELETE),
}

# ForEach-Object and Where-Object run their script block once per item that
# reaches them, with $_ bound to that item. `gci *.log | % { ri $_ }` deletes
# every .log - a line the old text rules escalated on sight and the engine
# now reads exactly.
_BLOCK_CMDLETS = {"ForEach-Object", "Where-Object"}

# A PowerShell drive that is not the filesystem: the registry, the
# environment, variables, certificates. They are not files, nothing local
# captures them, and guessing would be worse than saying so.
# `C:\x` is a drive letter - one letter. `HKLM:\Software`, `Env:PATH`,
# `Variable:x`, `Cert:\...` are PowerShell providers: not files, so nothing
# local captures them and the line is not understood.
_PROVIDER = re.compile(r"^[A-Za-z]{2,}:")

# Cmdlets that read and change nothing. Anything NOT listed and not handled
# below is uncovered - the table grows by measurement, never by assumption.
READS = frozenset({
    "Get-ChildItem", "Get-Item", "Get-Content", "Get-Location", "Get-Process",
    "Get-Service", "Get-Command", "Get-Help", "Get-Member", "Get-Date",
    "Get-Host", "Get-Variable", "Get-Alias", "Get-Module", "Get-Random",
    "Select-Object", "Select-String", "Where-Object", "Sort-Object",
    "Measure-Object", "Group-Object", "Compare-Object", "Format-List",
    "Format-Table", "Format-Wide", "Format-Custom", "Write-Output",
    "Write-Host", "Write-Verbose", "Write-Warning", "Write-Debug",
    "Write-Information", "Out-Null", "Out-String", "Out-Host", "Out-Default",
    "Test-Path", "Resolve-Path", "Join-Path", "Split-Path", "Convert-Path",
    "ConvertTo-Json", "ConvertFrom-Json", "ConvertTo-Csv", "ConvertFrom-Csv",
    "Import-Csv", "Export-Csv", "Tee-Object", "ForEach-Object", "Start-Sleep",
    "Read-Host", "Set-Location", "Push-Location", "Pop-Location",
})

# Runs code this engine does not read: the PowerShell side of ruling M1.
RUNNERS = frozenset({"Invoke-Expression", "Invoke-Command", "Start-Process",
                     "Start-Job", "Invoke-Item"})

# Downloads. Fetched code that then runs keeps the deny channel POSIX gives
# `curl ... | bash` (V12 / M2.3a).
FETCHERS = frozenset({"Invoke-WebRequest", "Invoke-RestMethod"})

_MAX_DEPTH = 6


class PsRunner:
    """Runs a parsed PowerShell script against an engine `World`."""

    def __init__(self, world) -> None:
        self.world = world
        self.impact = world.impact

    # -- paths ------------------------------------------------------------
    def _one_path(self, word: PsWord, state, cmd: PsCommand) -> Optional[str]:
        """One word as an absolute path, or None when it cannot be read."""
        raw = word.value
        if word.expands:
            # A variable this line SET is known: `$t = "notes.txt";
            # Remove-Item $t` deletes notes.txt, and reading it as unknown
            # would lose a capture the old text rules already made.
            known = self._known(word, state)
            if known is None:
                self.impact.not_understood(cmd.text, "a path built from a variable")
                return None
            raw = known
        if not raw:
            return None
        if _PROVIDER.match(raw):
            self.impact.not_understood(
                cmd.text, f"{raw.split(':')[0]}: is not the filesystem, so nothing local captures it")
            return None
        # Windows spellings work on both systems: the engine is tested on
        # Linux and runs on Windows, and a path must mean the same on each.
        drive = re.match(r"^[A-Za-z]:[\\/]", raw)
        path = raw.replace("\\", os.sep) if os.sep != "\\" else raw
        if drive and os.sep != "\\":
            # Tested on Linux, run on Windows. `C:\x` is absolute on both, but
            # os.path.normpath('C:/x') is RELATIVE here, so without this the
            # path quietly resolved inside the project and a write outside it
            # looked like a write to it.
            return os.path.normpath(os.sep + path)
        if state.cwd is None:
            self.impact.not_understood(cmd.text, "the working directory is unknown")
            return None
        return os.path.normpath(path if os.path.isabs(path)
                                else os.path.join(state.cwd, path))

    @staticmethod
    def _known(word: PsWord, state) -> Optional[str]:
        """The value of a word that is exactly one variable this line set."""
        if word.kind != "variable":
            return None
        value = state.vars.get(word.value.lstrip("$"))
        return value or None

    def paths(self, words: List[PsWord], state, cmd: PsCommand,
              literal: bool = False) -> List[str]:
        """Every path a list of bound words names, wildcards expanded.

        `literal` is -LiteralPath, where PowerShell expands nothing - which is
        the only way to name a file whose name holds [ ] (VERIFIED: -Path
        '[a].txt' reads the brackets as a character class and matches nothing).
        """
        out: List[str] = []
        for w in words:
            for v in w.values:
                p = self._one_path(v, state, cmd)
                if p is None:
                    continue
                if not literal and any(ch in p for ch in "*?["):
                    try:
                        out.extend(self.world.glob(state, p))
                    except Exception:
                        self.impact.not_understood(cmd.text, "a wildcard that matches too much")
                    continue
                out.append(p)
        return out

    # -- the pipeline -----------------------------------------------------
    def run_script(self, script: PsScript, state, depth: int = 0):
        if depth > _MAX_DEPTH:
            self.impact.not_understood(script.line[:80], "nested too deep to follow")
            return state
        for unit, why in script.not_understood:
            self.impact.not_understood(unit, why)
        for assign in script.assigns:
            # A variable whose value this engine did not compute is unknown,
            # which is what makes `$t = "x"; Remove-Item $t` honest: the
            # value IS known here, so the delete is read.
            if len(assign.words) == 1 and not assign.words[0].expands:
                state.vars[assign.name] = assign.words[0].value
            else:
                state.vars[assign.name] = None
        for pipe in script.pipelines:
            self.world.budget.check()
            state = self.run_pipeline(pipe.commands, state, depth)
        return state

    def run_pipeline(self, commands: List[PsCommand], state, depth: int):
        piped: Optional[PsWord] = None      # a value the previous element produced
        upstream_paths: List[str] = []      # files the previous element listed
        for cmd in commands:
            self.world.budget.check()
            if cmd.is_expression:
                piped, upstream_paths = cmd.value, []
                for w in cmd.words:
                    if w.nested is not None:
                        state = self.run_script(w.nested, state, depth + 1)
                # `"x" > a.txt` writes a.txt: the element is a value, but the
                # redirection hanging off it is still a write (A9, cnt_8).
                state = self._redirect(cmd, state)
                continue
            state, piped, upstream_paths = self.run_command(
                cmd, state, depth, piped, upstream_paths)
        return state

    # -- one command ------------------------------------------------------
    def run_command(self, cmd: PsCommand, state, depth: int,
                    piped: Optional[PsWord], upstream: List[str]):
        # $( ) runs BEFORE the command, whether it stands alone or sits
        # inside a double-quoted string: `Write-Output "$(Remove-Item a.txt)"`
        # deletes a.txt, and the quotes change nothing about that.
        for w in cmd.words:
            if w.nested is not None and w.kind in ("sub", "double"):
                state = self.run_script(w.nested, state, depth + 1)

        if not cmd.name:
            return state, None, []

        if cmd.words and cmd.words[0].expands:
            # `& $c`, `$_.Name`, a name built while it runs: what executes is
            # not knowable, so the line is not understood - never "no effect"
            # (A9, pipe_4: a filter block made the whole pipeline look empty).
            self.impact.not_understood(cmd.text, "the command word is not known before it runs")
            return state, None, []

        if cmd.name.lower().endswith(".ps1") or "/" in cmd.name or "\\" in cmd.name:
            # `.\cleanup.ps1`, `& C:\x.ps1`: a script this engine does not
            # read - a runner, exactly like `python x.py` on POSIX (M1).
            self.impact.not_covered(os.path.basename(cmd.name.replace("\\", "/")))
            return state, None, []

        surface = SURFACES.get(cmd.name.lower())
        if surface is not None:
            label, kind = surface
            self.impact.reach(label, kind)
            return state, None, []

        bound = ps_bind.bind(cmd, piped_value=piped)
        if bound.native:
            return self._native(cmd, state, depth)
        if bound.uncovered:
            self.impact.not_understood(cmd.text, bound.uncovered)
            self.impact.refused.append((cmd.text, bound.uncovered))
            return state, None, []

        name = bound.cmdlet or ""
        # PS4: -WhatIf means PowerShell only DESCRIBES the action.
        if bound.has("WhatIf"):
            return state, None, []

        if name in _BLOCK_CMDLETS:
            state = self._blocks(cmd, state, depth, upstream)
            passthrough = upstream if name == "Where-Object" else []
            return state, None, passthrough

        handler = _HANDLERS.get(name)
        if handler is not None:
            handler(self, cmd, bound, state, depth, upstream)
            state = self._redirect(cmd, state)
            return state, None, self._listed(name, bound, state, cmd)
        if name in READS:
            state = self._redirect(cmd, state)
            return state, None, self._listed(name, bound, state, cmd)
        if name in FETCHERS:
            self.impact.not_understood(cmd.text, "it downloads something demo_cli cannot read")
            return state, None, []
        if name in RUNNERS:
            return self._runner(name, cmd, bound, state, depth)
        self.impact.not_covered(name)
        return state, None, []

    def _blocks(self, cmd: PsCommand, state, depth: int, upstream: List[str]):
        """Run a script block once per item the pipeline fed it, with $_ set.

        With nothing readable upstream the block still runs once, with $_
        unknown - so a delete inside it is reported as a line that could not
        be read rather than as nothing at all.
        """
        blocks = [w for w in cmd.words if w.kind == "block" and w.nested is not None]
        if not blocks:
            return state
        saved = state.vars.get("_")
        items = upstream or [None]
        for item in items:
            state.vars["_"] = item
            for w in blocks:
                state = self.run_script(w.nested, state, depth + 1)
        state.vars["_"] = saved
        return state

    def _listed(self, name: str, bound, state, cmd: PsCommand) -> List[str]:
        """What a listing puts on the pipeline, so `Get-ChildItem *.tmp |
        Remove-Item` deletes what the listing returns (A8 case 10_2)."""
        if name not in ("Get-ChildItem", "Get-Item"):
            return []
        words = bound.values("Path", "LiteralPath")
        if not words:
            return [p for p in self.world.glob(state, os.path.join(state.cwd or ".", "*"))] \
                if state.cwd else []
        return self.paths(words, state, cmd, literal=bool(bound.params.get("LiteralPath")))

    def _redirect(self, cmd: PsCommand, state):
        """`> file` overwrites, `>> file` appends - the same as Out-File."""
        for r in cmd.redirects:
            # `2> log`, `*> log` and `>` all WRITE that file; only the `&1`
            # forms merge one stream into another and touch nothing.
            if r.target is None or r.op.endswith("&1"):
                continue
            p = self._one_path(r.target, state, cmd)
            if p is not None:
                self.world.write(state, p, appending=r.op == ">>")
        return state

    def _native(self, cmd: PsCommand, state, depth: int):
        """A program, not a cmdlet. PowerShell passes the words through, so
        the POSIX engine - which knows git, npm, python and the rest - reads
        the line. `cmd /c ...` keeps the old text rules (ruling PS3)."""
        from ..model import parse as posix_parse
        head = cmd.name.lower()
        if head in ("cmd", "cmd.exe"):
            self.impact.not_covered("cmd")
            self.impact.not_understood(cmd.text, "cmd.exe: read by the text rules, not the engine")
            return state, None, []
        if head in ("powershell", "powershell.exe", "pwsh", "pwsh.exe"):
            return self._nested_powershell(cmd, state, depth)
        if "`" in cmd.text or any(w.kind == "here" for w in cmd.words):
            # The backtick is PowerShell's escape and POSIX's nothing, and a
            # here-string has no POSIX spelling: re-reading such a line with
            # the POSIX parser would read a DIFFERENT command.
            self.impact.not_understood(cmd.text, "PowerShell quoting inside a program's arguments")
            return state, None, []
        try:
            state = self.world.run_script(posix_parse(cmd.text), state, depth + 1)
        except Exception:
            self.impact.not_understood(cmd.text, "a program demo_cli could not read")
        return state, None, []

    def _nested_powershell(self, cmd: PsCommand, state, depth: int):
        """powershell -Command "..." and -EncodedCommand <base64>."""
        words = cmd.args
        for k, w in enumerate(words):
            if not w.is_param:
                continue
            low = (w.param_name or "").lower()
            payload = w.param_value or (words[k + 1] if k + 1 < len(words)
                                        and not words[k + 1].is_param else None)
            if payload is None:
                continue
            if "encodedcommand".startswith(low) and len(low) >= 2:
                try:
                    text = base64.b64decode(payload.value).decode("utf-16-le")
                except Exception:
                    self.impact.not_understood(cmd.text, "an encoded command that cannot be decoded")
                    return state, None, []
                state = self.run_script(ps_parse(text), state, depth + 1)
                return state, None, []
            if low and "command".startswith(low):
                if payload.expands:
                    self.impact.not_understood(cmd.text, "a command built while it runs")
                    return state, None, []
                state = self.run_script(ps_parse(payload.value), state, depth + 1)
                return state, None, []
            if low and "file".startswith(low):
                # A script file is a RUNNER (M1), like `python x.py` and
                # `.\x.ps1` - not an unreadable line.
                if payload.expands:
                    self.impact.not_understood(cmd.text, "a script file named by a variable")
                else:
                    self.impact.not_covered(os.path.basename(payload.value.replace("\\", "/")))
                return state, None, []
        self.impact.not_understood(cmd.text, "a nested PowerShell this engine could not read")
        return state, None, []

    def _runner(self, name: str, cmd: PsCommand, bound, state, depth: int):
        """Invoke-Expression and friends: code given as text."""
        if name == "Invoke-Expression":
            words = bound.values("Command") or [w for w in cmd.args if not w.is_param]
            target = words[0] if words else None
            if target is None or target.expands:
                self.impact.not_understood(
                    cmd.text, "Invoke-Expression runs a string built while it runs")
                return state, None, []
            state = self.run_script(ps_parse(target.value), state, depth + 1)
            return state, None, []
        self.impact.not_covered(name)
        self.impact.not_understood(cmd.text, f"{name} runs code demo_cli does not read")
        return state, None, []


# --------------------------------------------------------------------------
# The cmdlet handlers. One per effect, each matching a measured behaviour.
# --------------------------------------------------------------------------

def _target_words(bound):
    return bound.values("Path", "LiteralPath", "FilePath")


def _literal(bound) -> bool:
    return bool(bound.params.get("LiteralPath"))


def _h_remove_item(run: PsRunner, cmd, bound, state, depth, upstream):
    words = _target_words(bound)
    paths = run.paths(words, state, cmd, literal=_literal(bound)) if words else list(upstream)
    if bound.params.get("Include") or bound.params.get("Exclude") or bound.params.get("Filter"):
        run.impact.not_understood(
            cmd.text, "-Include / -Exclude / -Filter: what they match depends on the path's shape")
        return
    recursive = bound.has("Recurse")
    for p in paths:
        node = run.world.node(state, p)
        if not node.exists:
            continue
        if node.is_dir and not recursive and not run.world.is_empty(state, p):
            # It asks first. A person may say yes, so it stays a delete.
            run.impact.not_understood(
                cmd.text, "Remove-Item on a directory that is not empty asks before deleting")
        run.world.remove(state, p)


def _h_clear_content(run: PsRunner, cmd, bound, state, depth, upstream):
    for p in run.paths(_target_words(bound), state, cmd, literal=_literal(bound)) or upstream:
        node = run.world.node(state, p)
        if node.exists and not node.is_dir:
            run.world.replace(state, p, TRUNCATE)


def _h_set_content(run: PsRunner, cmd, bound, state, depth, upstream):
    """Set-Content / Out-File: overwrite an existing file, else create it.
    Out-File -Append appends; Out-File -NoClobber on an existing file is an
    error and changes nothing. Set-Content has neither parameter."""
    appending = bound.has("Append")
    for p in run.paths(_target_words(bound), state, cmd, literal=_literal(bound)) or upstream:
        if bound.has("NoClobber") and run.world.node(state, p).exists:
            continue
        run.world.write(state, p, appending=appending)


def _h_add_content(run: PsRunner, cmd, bound, state, depth, upstream):
    for p in run.paths(_target_words(bound), state, cmd, literal=_literal(bound)) or upstream:
        run.world.write(state, p, appending=True)


def _h_copy_item(run: PsRunner, cmd, bound, state, depth, upstream):
    """Copy-Item OVERWRITES an existing destination with no -Force. Copying a
    directory without -Recurse creates an EMPTY directory and copies nothing."""
    srcs = run.paths(_target_words(bound), state, cmd, literal=_literal(bound)) or upstream
    dests = run.paths(bound.values("Destination"), state, cmd)
    if not srcs or not dests:
        if srcs and not dests:
            run.impact.not_understood(cmd.text, "Copy-Item without a destination")
        return
    dest = dests[0]
    dnode = run.world.node(state, dest)
    for src in srcs:
        snode = run.world.node(state, src)
        if not snode.exists:
            continue
        if snode.is_dir and not bound.has("Recurse"):
            run.world.mkdir(state, os.path.join(dest, os.path.basename(src))
                            if dnode.exists and dnode.is_dir else dest, False)
            continue
        target = (os.path.join(dest, os.path.basename(src))
                  if dnode.exists and dnode.is_dir else dest)
        tnode = run.world.node(state, target)
        if tnode.exists and not tnode.is_dir:
            run.world.replace(state, target, OVERWRITE)
        else:
            run.world.create(state, target)


def _h_move_item(run: PsRunner, cmd, bound, state, depth, upstream):
    """Move-Item refuses an existing destination WITHOUT -Force; with -Force
    the destination's content is lost."""
    srcs = run.paths(_target_words(bound), state, cmd, literal=_literal(bound)) or upstream
    dests = run.paths(bound.values("Destination"), state, cmd)
    if not srcs or not dests:
        return
    dest = dests[0]
    dnode = run.world.node(state, dest)
    for src in srcs:
        if not run.world.node(state, src).exists:
            continue
        target = (os.path.join(dest, os.path.basename(src))
                  if dnode.exists and dnode.is_dir else dest)
        tnode = run.world.node(state, target)
        if tnode.exists and not bound.has("Force"):
            continue                                     # it refuses: nothing happens
        run.world.move(state, [(src, target)], _NoFlags())


def _h_rename_item(run: PsRunner, cmd, bound, state, depth, upstream):
    """Rename-Item REFUSES an existing destination even with -Force (5.1)."""
    srcs = run.paths(_target_words(bound), state, cmd, literal=_literal(bound)) or upstream
    news = bound.values("NewName")
    if not srcs or not news:
        return
    new = news[0]
    if new.expands:
        run.impact.not_understood(cmd.text, "a new name built from a variable")
        return
    for src in srcs:
        if not run.world.node(state, src).exists:
            continue
        target = os.path.join(os.path.dirname(src), new.value.replace("\\", os.sep))
        if run.world.node(state, target).exists:
            continue                                     # refused, with or without -Force
        run.world.move(state, [(src, target)], _NoFlags())


def _h_new_item(run: PsRunner, cmd, bound, state, depth, upstream):
    """New-Item -Force on an existing FILE truncates it to zero bytes; on an
    existing DIRECTORY it keeps everything inside."""
    is_dir = any(w.value.lower() == "directory" for w in bound.values("ItemType"))
    for p in run.paths(_target_words(bound) or bound.values("Name"), state, cmd):
        node = run.world.node(state, p)
        if node.exists:
            if not bound.has("Force") or node.is_dir:
                continue                                 # an error, or a kept directory
            run.world.replace(state, p, TRUNCATE)
            continue
        if is_dir:
            run.world.mkdir(state, p, True)
        else:
            run.world.create(state, p)


class _NoFlags:
    """world.move / world.copy expect a parsed POSIX option set; PowerShell
    has no -b/--backup and no --no-clobber, so these are always empty."""
    flags: frozenset = frozenset()
    options: dict = {}
    operands: tuple = ()


_HANDLERS = {
    "Remove-Item": _h_remove_item,
    "Clear-Content": _h_clear_content,
    "Set-Content": _h_set_content,
    "Out-File": _h_set_content,
    "Add-Content": _h_add_content,
    "Copy-Item": _h_copy_item,
    "Move-Item": _h_move_item,
    "Rename-Item": _h_rename_item,
    "New-Item": _h_new_item,
}


def run(world, line: str, state, depth: int = 0):
    """Entry point: run one PowerShell line on `world`."""
    return PsRunner(world).run_script(ps_parse(line), state, depth)
