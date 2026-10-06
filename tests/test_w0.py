from __future__ import annotations

import os
from pathlib import Path

import pytest

from conftest import assert_restores
from demo_cli.config import Config
from demo_cli.engine.simulate import simulate
from demo_cli.guard import Guard, agent_directory
from demo_cli.model import posix_units


def _rel_destroys(imp, root: Path) -> set[str]:
    return {os.path.relpath(p, str(root)).replace("\\", "/") for p in imp.destroys}


# ------------------------------------------------------------------------------
# Test 1: The decoder matches bash
# ------------------------------------------------------------------------------

def test_1_the_decoder_matches_bash():
    from demo_cli.model import ansi_c

    # 1. Simple control characters (\a \b \e \E \f \n \r \t \v)
    assert ansi_c("\\a") == "\a"
    assert ansi_c("\\b") == "\b"
    assert ansi_c("\\e") == "\x1b"
    assert ansi_c("\\E") == "\x1b"
    assert ansi_c("\\f") == "\f"
    assert ansi_c("\\n") == "\n"
    assert ansi_c("\\r") == "\r"
    assert ansi_c("\\t") == "\t"
    assert ansi_c("\\v") == "\v"

    # 2. The character itself (\\ \' \" \?)
    assert ansi_c("\\\\") == "\\"
    assert ansi_c("\\'") == "'"
    assert ansi_c('\\"') == '"'
    assert ansi_c("\\?") == "?"

    # 3. Octal digits (\NNN, 1 to 3 digits; boundary: 3-digit octal followed by a digit)
    assert ansi_c("\\101") == "A"
    assert ansi_c("\\1011") == "A1"

    # 4. Hex digits (\xHH, 1 to 2 hex digits; boundary: 2-digit hex followed by a digit)
    assert ansi_c("\\x41") == "A"
    assert ansi_c("\\x414") == "A4"

    # 5. \x with no hex digit (kept as written)
    assert ansi_c("\\x") == "\\x"

    # 6. Any other escape (\q, \8; kept as written)
    assert ansi_c("\\q") == "\\q"
    assert ansi_c("\\8") == "\\8"

    # 7. Zero octal/hex (bash cuts the word; not decoded here)
    assert ansi_c("\\0") is None
    assert ansi_c("\\000") is None
    assert ansi_c("\\x00") is None

    # 8. Control / locale-dependent (\cX, \u, \U; not decoded here)
    assert ansi_c("\\cA") is None
    assert ansi_c("\\u0041") is None
    assert ansi_c("\\U00000041") is None


# ------------------------------------------------------------------------------
# Test 2: The engine reads decoded words
# ------------------------------------------------------------------------------

def test_2_the_engine_reads_decoded_words(tmp_path):
    root = tmp_path / "p"
    root.mkdir(parents=True, exist_ok=True)
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "src" / "m.py").write_bytes(b"m")
    (root / "a.txt").write_bytes(b"content")

    cases = [
        # pass2b rows from inventory
        ("$'\\x72\\x6d' -rf src", {"src"}, []),
        ("$'\\162\\155' -rf src", {"src"}, []),
        ("rm $'-rf' src", {"src"}, []),
        ("r\\m -rf src", {"src"}, []),
        ('"r"m -rf src', {"src"}, []),
        ("X=rm; $X -rf src", {"src"}, []),
        ("${X:-rm} -rf src", set(), ["the command word: parameter expansion ${X:-rm}"]),
        ("git $'push' --force", set(), []),
        # argument with hex escape naming existing file
        ("rm $'a\\x2etxt'", {"a.txt"}, []),
        # undecoded escape (\u) as argument
        ("rm $'\\u0061.txt'", set(), ["an ANSI-C escape this engine does not decode"]),
        # undecoded escape (\u) as command word
        ("$'\\u0072\\u006d' -rf src", set(), ["the command word: an ANSI-C escape this engine does not decode"]),
    ]

    for cmd, want_destroys, want_unknown in cases:
        imp = simulate(cmd, cwd=str(root), budget_ms=10_000)
        assert _rel_destroys(imp, root) == want_destroys, cmd
        assert [why for _u, why in imp.unknown] == want_unknown, cmd


# ------------------------------------------------------------------------------
# Test 3: The old path reads decoded words
# ------------------------------------------------------------------------------

def test_3_the_old_path_reads_decoded_words(tmp_path):
    root = tmp_path / "p"
    root.mkdir(parents=True, exist_ok=True)

    # 1. posix_units returns decoded plain text
    assert posix_units("$'git' push --force") == (("git push --force", "posix", ""),)
    assert posix_units("git $'push' --force") == (("git push --force", "posix", ""),)

    # 2. Guard.evaluate gives the old rule's decision
    cfg = Config(project_root=str(root), mode="enforce")
    g = Guard(cfg)
    with agent_directory(str(root)):
        r1 = g.evaluate("$'git' push --force", door="agent")
        r2 = g.evaluate("git $'push' --force", door="agent")
    assert r1.decision.decision == "ESCALATE"
    assert r1.classification.matched_rule == "git_force_push"
    assert r1.classification.nonrecoverable_surface == "remote_vcs_history"
    assert r2.decision.decision == "ESCALATE"
    assert r2.classification.matched_rule == "git_force_push"
    assert r2.classification.nonrecoverable_surface == "remote_vcs_history"


# ------------------------------------------------------------------------------
# Test 4: The decision
# ------------------------------------------------------------------------------

def test_4_the_decision(tmp_path):
    root = tmp_path / "p"
    root.mkdir(parents=True, exist_ok=True)
    src = root / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "m.py").write_bytes(b"m")

    cfg = Config(project_root=str(root), mode="enforce")
    g = Guard(cfg)
    with agent_directory(str(root)):
        r = g.evaluate("$'\\x72\\x6d' -rf src", door="agent")
    assert r.decision.decision == "REVERSIBLE"
    assert r.recovery_entry is not None
    assert_restores(r.recovery_entry, str(root), {"src/m.py": b"m"})

