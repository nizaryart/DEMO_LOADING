"""What each cmdlet does, written as data, with the examples that prove it.

The POSIX table (rules.py) carries its grammar and its examples together, and
every example runs as a test. This is the same thing for PowerShell: the
EFFECTS live in ps_ops.py, because they are expressed by calling the shared
world rather than by an option template, but the CLAIMS about each cmdlet
live here, next to the line that demonstrates them.

Every claim below was measured on PowerShell 5.1.19041 in a throwaway
directory (the sandbox runs of 2026-10-10), not taken from documentation.
Where the measurement contradicted the obvious reading, the example says so.

tests/test_c3_rules.py runs every example. A cmdlet with no example here is
a cmdlet nobody has pinned, which is why the test also refuses a family that
carries none.
"""
from __future__ import annotations

from .rules import Example, ex

# The fixture every example runs in (tests/test_c3_rules.py builds it):
#   a.txt b.txt log.txt notes.md   files with content
#   dist/out.o                     a directory with one file
#   t1.tmp t2.tmp                  two files a wildcard can match
#   emptydir/                      an empty directory

PS_FAMILIES: dict = {
    "Remove-Item": (
        ex("Remove-Item a.txt", destroys={"a.txt"}),
        ex("Remove-Item -Recurse -Force dist", destroys={"dist/"}),
        ex("Remove-Item -Rec dist", destroys={"dist/"},
           note="the shortest unambiguous prefix of -Recurse"),
        ex("Remove-Item a.txt, b.txt", destroys={"a.txt", "b.txt"},
           note="an array binds as one value list to -Path"),
        ex("Remove-Item *.tmp", destroys={"t1.tmp", "t2.tmp"}),
        ex("Remove-Item -LiteralPath a.txt", destroys={"a.txt"}),
        ex("Remove-Item ghost", note="nothing there: nothing is destroyed"),
        ex("Remove-Item emptydir", destroys={"emptydir/"},
           note="an EMPTY directory needs no -Recurse"),
        ex("Remove-Item a.txt -WhatIf", note="PS4: -WhatIf only describes the action"),
        ex("Remove-Item a.txt -F", unknown=True,
           note="VERIFIED: -F matches -Filter AND -Force; PowerShell binds nothing"),
        ex("Remove-Item -Path dist -Include *.o", unknown=True,
           note="VERIFIED: -Include is ignored unless the path ends in a wildcard"),
        ex("Remove-Item HKLM:\\Software\\X", unknown=True,
           note="a provider that is not the filesystem"),
    ),
    "Clear-Content": (
        ex("Clear-Content log.txt", destroys={"log.txt"}),
        ex("clc log.txt", destroys={"log.txt"}),
        ex("Clear-Content ghost", note="nothing there"),
    ),
    "Set-Content": (
        ex("Set-Content a.txt hi", destroys={"a.txt"},
           note="positional: a.txt is -Path (0), hi is -Value (1)"),
        ex("Set-Content -Path a.txt -Value hi", destroys={"a.txt"}),
        ex("Set-Content brand_new.txt hi", creates={"brand_new.txt"}),
        ex("Set-Content a.txt -Append", unknown=True,
           note="VERIFIED: Set-Content has NO -Append - a binding error, nothing runs"),
    ),
    "Out-File": (
        ex("Out-File -FilePath a.txt", destroys={"a.txt"}),
        ex("Out-File -NoClobber a.txt",
           note="VERIFIED: -NoClobber on an existing file is an error; nothing is written"),
        ex("Out-File -Append a.txt", changes={"a.txt"}),
    ),
    "Add-Content": (
        ex("Add-Content log.txt more", changes={"log.txt"}, note="appending destroys nothing"),
        ex("ac log.txt more", changes={"log.txt"}),
    ),
    "Copy-Item": (
        ex("Copy-Item a.txt b.txt", destroys={"b.txt"},
           note="VERIFIED: it overwrites a writable destination with NO -Force"),
        ex("Copy-Item a.txt new.txt", creates={"new.txt"}),
        ex("Copy-Item a.txt dist", creates={"dist/a.txt"}, note="into an existing directory"),
    ),
    "Move-Item": (
        ex("Move-Item a.txt b.txt",
           note="VERIFIED: it REFUSES an existing destination without -Force"),
        ex("Move-Item -Force a.txt b.txt", destroys={"b.txt"}),
        ex("Move-Item a.txt new.txt",
           note="a move onto a free name destroys nothing - as POSIX `mv a.txt new.txt`"),
    ),
    "Rename-Item": (
        ex("Rename-Item a.txt b.txt",
           note="VERIFIED: an existing destination is refused"),
        ex("Rename-Item -Force a.txt b.txt",
           note="VERIFIED: refused EVEN WITH -Force, unlike Move-Item"),
        ex("Rename-Item a.txt renamed.txt",
           note="a rename onto a free name destroys nothing - Rename-Item never destroys"),
    ),
    "New-Item": (
        ex("New-Item new.txt -ItemType File", creates={"new.txt"}),
        ex("New-Item a.txt -ItemType File",
           note="VERIFIED: an existing file without -Force is an error"),
        ex("New-Item a.txt -ItemType File -Force", destroys={"a.txt"},
           note="VERIFIED: -Force empties the file to zero bytes"),
        ex("New-Item dist -ItemType Directory -Force",
           note="VERIFIED: an existing directory keeps everything inside it"),
        ex("New-Item newdir -ItemType Directory", creates={"newdir"}),
    ),
    "pipeline": (
        ex('"a.txt" | Remove-Item', destroys={"a.txt"}, note="a value binds ByValue to -Path"),
        ex("Get-ChildItem *.tmp | Remove-Item", destroys={"t1.tmp", "t2.tmp"},
           note="VERIFIED: the FileInfo binds ByPropertyName"),
        ex("gci *.tmp | % { ri $_ }", destroys={"t1.tmp", "t2.tmp"},
           note="a script block runs once per item, with $_ bound"),
    ),
    "code in code": (
        ex('iex "Remove-Item a.txt"', destroys={"a.txt"}, note="a literal string is a line"),
        ex('Write-Output "$(Remove-Item a.txt)"', destroys={"a.txt"},
           note="a sub-expression runs even inside quotes"),
        ex("iex $cmd", unknown=True, note="a string built while it runs cannot be read"),
    ),
    "redirection": (
        ex("Get-Process > log.txt", destroys={"log.txt"}),
        ex("Get-Process >> log.txt", changes={"log.txt"}),
        ex("Get-Process 2> log.txt", destroys={"log.txt"},
           note="the error stream writes the file too"),
        ex("Get-Process > brand_new.txt", creates={"brand_new.txt"}),
    ),
    "reads": (
        ex("Get-ChildItem"),
        ex("Get-Content a.txt"),
        ex("Test-Path a.txt"),
        ex("Get-Item a.txt | Select-Object FullName | Format-List"),
    ),
}


def all_examples():
    """[(family, Example)] for every claim in this table."""
    return [(family, e) for family, examples in PS_FAMILIES.items() for e in examples]
