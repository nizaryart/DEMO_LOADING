"""C3's reading, checked against PowerShell's own parser (ruling PS1).

demo_cli parses PowerShell itself, because starting powershell.exe on the
hook's hot path would cost hundreds of milliseconds and the guard must also
answer from WSL. The price of owning a parser is the risk of reading a line
differently from the shell that will run it - so PowerShell's parser is used
here as an ORACLE: one process, one pass over the corpus, and every line's
command names, parameters and arguments compared with ours.

WINDOWS ONLY: it needs a real PowerShell. On Linux the test skips, exactly
as the ptrace tests do in reverse.

The corpus is written here rather than mined from a machine: the lines an
agent really ran hold personal paths, and a test fixture committed to the
repository must not. Each line below stands for a construct the binder has
to get right, and the set was chosen from what the ledgers and the agent
session logs actually contain (A8, 2026-10-10): pipelines, here-strings,
positional and named parameters, arrays, sub-expressions, script blocks,
aliases, and native programs mixed in with cmdlets.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

import pytest

pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="the oracle is PowerShell's own parser, which exists on Windows")

from demo_cli.engine.ps_tables_data import ALIASES, CMDLETS   # noqa: E402
from demo_cli.ps_model import commands_of, parse              # noqa: E402

CORPUS = [
    "Get-ChildItem",
    "Get-Content -Raw README.md",
    "Remove-Item logs\\app.log",
    "Remove-Item -Recurse -Force build",
    "Remove-Item -LiteralPath .\\important.txt",
    "Remove-Item a.txt, b.txt",
    "Remove-Item -Rec dist",
    "Set-Content a.txt hi",
    "Set-Content -Path a.txt -Value \"x y\"",
    "Add-Content log.txt 'one more'",
    "Copy-Item a.txt b.txt",
    "Move-Item -Force a.txt b.txt",
    "Rename-Item a.txt b.txt",
    "New-Item -ItemType Directory -Force out",
    "Clear-Content log.txt",
    "Out-File -NoClobber new.txt",
    "\"a.txt\" | Remove-Item",
    "Get-ChildItem *.tmp | Remove-Item",
    "Get-Item -LiteralPath .\\x.txt | Select-Object FullName,Length | Format-List",
    "Get-Process chrome -ErrorAction SilentlyContinue | Select-Object Id, ProcessName",
    "Get-Command python, node -ErrorAction SilentlyContinue | Select-Object Name, Source",
    "gci *.log | % { ri $_ }",
    "Get-ChildItem | ForEach-Object { Remove-Item $_.FullName }",
    "$t = \"notes.txt\"; Remove-Item $t",
    "Set-Content -Path $env:TEMP\\notes.txt -Value x",
    "Write-Output \"$(Get-Date)\"",
    "Remove-Item -Confirm:$false a.txt",
    "Remove-Item a.txt -WhatIf",
    "Get-Process | Out-File out.txt",
    "Get-Process 2> errors.txt",
    "echo hello",
    "python --version; node --version",
    "git push --force",
    "Test-Path \"C:\\Program Files\\Git\\bin\\git.exe\"",
    "Remove-Item `\n  -Recurse -Force C:\\build",
    "@'\nline one\nline two\n'@ | Set-Content -Path out.txt",
]

_DUMP = r"""
param([string]$In, [string]$Out)
$lines = Get-Content -Raw -LiteralPath $In | ConvertFrom-Json
$all = @()
foreach ($line in $lines) {
  $errors = $null; $tokens = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseInput($line, [ref]$tokens, [ref]$errors)
  $cmds = @()
  foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $name = $c.GetCommandName()
    $params = @(); $args_ = @()
    for ($i = 1; $i -lt $c.CommandElements.Count; $i++) {
      $e = $c.CommandElements[$i]
      if ($e -is [System.Management.Automation.Language.CommandParameterAst]) {
        $params += $e.ParameterName
      } else { $args_ += $e.Extent.Text }
    }
    $cmds += [ordered]@{ name = $name; parameters = $params; arguments = $args_ }
  }
  $all += , [ordered]@{ line = $line; errors = @($errors | ForEach-Object { $_.Message });
                        commands = $cmds }
}
$json = $all | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($Out, $json, (New-Object System.Text.UTF8Encoding($false)))
"""


def _oracle(tmp_path):
    """One powershell.exe run for the whole corpus - never one per line."""
    script = tmp_path / "oracle.ps1"
    script.write_text(_DUMP, encoding="utf-8")
    src = tmp_path / "corpus.json"
    src.write_text(json.dumps(CORPUS), encoding="utf-8")
    out = tmp_path / "oracle.json"
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(script), "-In", str(src), "-Out", str(out)],
        capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not out.exists():
        pytest.skip(f"PowerShell could not parse the corpus: {proc.stderr.strip()[:200]}")
    return json.loads(out.read_text(encoding="utf-8"))


def _is_cmdlet(name: str) -> bool:
    low = name.lower()
    return low in {k.lower() for k in CMDLETS} or low in {k.lower() for k in ALIASES}


def test_our_parse_matches_powershells_own_parse(tmp_path):
    rows = _oracle(tmp_path)
    assert len(rows) == len(CORPUS), "the oracle answered for every line"
    problems = []
    for row in rows:
        line = row["line"]
        assert not row["errors"], f"the corpus line is not valid PowerShell: {line!r}"
        theirs = [c for c in row["commands"] if c.get("name")]
        ours = [c for c in commands_of(parse(line)) if c.name and not c.is_expression]
        for k, their in enumerate(theirs):
            if k >= len(ours):
                problems.append(f"{line!r}: we missed the command {their['name']!r}")
                break
            our = ours[k]
            if our.name.lower() != their["name"].lower():
                problems.append(f"{line!r}: command {their['name']!r} vs ours {our.name!r}")
                continue
            if not _is_cmdlet(our.name):
                continue        # a native program binds nothing: PowerShell passes its words through
            want = sorted(p.lower() for p in their["parameters"])
            got = sorted(w.param_name.lower() for w in our.args if w.is_param)
            if want != got:
                problems.append(f"{line!r}: {our.name} parameters {want} vs ours {got}")
            n_args = len([w for w in our.args if not w.is_param])
            if len(their["arguments"]) != n_args:
                problems.append(
                    f"{line!r}: {our.name} {len(their['arguments'])} arguments vs ours {n_args}")
    assert not problems, "\n".join(problems[:12])


def test_the_oracle_would_notice_a_wrong_parse(tmp_path):
    """The control: a reading PowerShell does NOT share must be caught.

    Without this, a comparison that silently matched nothing would pass.
    """
    rows = {r["line"]: r for r in _oracle(tmp_path)}
    row = rows["Set-Content a.txt hi"]
    assert [c["name"] for c in row["commands"] if c.get("name")] == ["Set-Content"]
    assert row["commands"][0]["arguments"] == ["a.txt", "hi"], (
        "PowerShell reads both as arguments; the BINDER is what makes them -Path and -Value")
