from __future__ import annotations

import os
from pathlib import Path

import pytest

from conftest import assert_restores
from demo_cli.config import Config
from demo_cli.engine.simulate import simulate
from demo_cli.guard import Guard, agent_directory
from demo_cli.model import parse
from demo_cli import syscall_guard


def _setup_fixtures(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "p"
    root.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "o.txt"
    outside.write_bytes(b"a.txt\n")

    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "a.txt").write_bytes(b"A")
    (root / "b.txt").write_bytes(b"B")
    (root / "a-b").write_bytes(b"x")
    (root / "c-").write_bytes(b"x")
    (root / "a.txt.bak").write_bytes(b"k")
    (root / "src" / "m.py").write_bytes(b"m")
    (root / "list.txt").write_bytes(b"a.txt\nb.txt\n")
    (root / "crlf.txt").write_bytes(b"a.txt\r\nb.txt\r\nend\n")
    (root / "vt.txt").write_bytes(b"a.txt\x0bb.txt\n")
    (root / "sp.txt").write_bytes(b"a.txt \t b.txt\n\n\n")
    (root / "opts.txt").write_bytes(b"-rf src\n")
    (root / "zero.txt").write_bytes(b"a.txt\x00\n")
    (root / "bad.txt").write_bytes(b"a\xff.txt\n")
    (root / "big.txt").write_bytes(b"a" * (64 * 1024 + 1))
    (root / "d.txt").write_bytes(b"src\n")
    return root, outside


def _rel_destroys(imp, root: Path) -> set[str]:
    return {os.path.relpath(p, str(root)).replace("\\", "/") for p in imp.destroys}


# ------------------------------------------------------------------------------
# Test 1: cat is read
# ------------------------------------------------------------------------------

def test_1_cat_is_read(tmp_path):
    root, _ = _setup_fixtures(tmp_path)

    # 1. rm $(cat list.txt)
    imp1 = simulate("rm $(cat list.txt)", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp1, root) == {"a.txt", "b.txt"}
    assert imp1.unknown == []
    assert imp1.computed == [("cat list.txt", "a.txt\nb.txt")]

    # 2. rm `cat list.txt`
    imp2 = simulate("rm `cat list.txt`", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp2, root) == {"a.txt", "b.txt"}
    assert imp2.unknown == []

    # 3. rm $(<list.txt)
    imp3 = simulate("rm $(<list.txt)", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp3, root) == {"a.txt", "b.txt"}
    assert imp3.unknown == []
    assert imp3.computed == [("<list.txt", "a.txt\nb.txt")]

    # 4. X=$(cat list.txt); rm $X
    imp4 = simulate("X=$(cat list.txt); rm $X", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp4, root) == {"a.txt", "b.txt"}
    assert imp4.unknown == []

    # 5. rm "$(cat list.txt)"
    imp5 = simulate('rm "$(cat list.txt)"', cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp5, root) == set()
    assert imp5.unknown == []

    # 6. rm $(cat 2>/dev/null list.txt)
    imp6 = simulate("rm $(cat 2>/dev/null list.txt)", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp6, root) == {"a.txt", "b.txt"}
    assert imp6.unknown == []


# ------------------------------------------------------------------------------
# Test 2: splitting is bash
# ------------------------------------------------------------------------------

def test_2_splitting_is_bash(tmp_path):
    root, _ = _setup_fixtures(tmp_path)

    # 1. crlf.txt: names keep \r
    imp1 = simulate("rm $(cat crlf.txt)", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp1, root) == set()
    assert imp1.unknown == []
    assert imp1.computed == [("cat crlf.txt", "a.txt\r\nb.txt\r\nend")]

    # 2. vt.txt: \v does not split
    imp2 = simulate("rm $(cat vt.txt)", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp2, root) == set()
    assert imp2.unknown == []

    # 3. sp.txt: spaces, tabs, newlines split
    imp3 = simulate("rm $(cat sp.txt)", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp3, root) == {"a.txt", "b.txt"}
    assert imp3.unknown == []

    # Glob in separate dir q
    q = tmp_path / "q"
    q.mkdir(parents=True, exist_ok=True)
    (q / "a.txt").write_bytes(b"A")
    (q / "b.txt").write_bytes(b"B")
    (q / "g.txt").write_bytes(b"*.txt\n")

    imp_g1 = simulate("rm $(cat g.txt)", cwd=str(q), budget_ms=10_000)
    assert _rel_destroys(imp_g1, q) == {"a.txt", "b.txt", "g.txt"}
    assert imp_g1.unknown == []

    imp_g2 = simulate('rm "$(cat g.txt)"', cwd=str(q), budget_ms=10_000)
    assert _rel_destroys(imp_g2, q) == set()
    assert imp_g2.unknown == []


# ------------------------------------------------------------------------------
# Test 3: echo, printf, pwd, basename, dirname
# ------------------------------------------------------------------------------

def test_3_echo_printf_pwd_basename_dirname(tmp_path):
    root, _ = _setup_fixtures(tmp_path)

    cmds = [
        ("rm $(echo a.txt b.txt)", {"a.txt", "b.txt"}),
        ("rm $(echo -n a.txt)", {"a.txt"}),
        ("rm $(printf '%s\\n' a.txt b.txt)", {"a.txt", "b.txt"}),
        ("rm $(printf '%s-%s\\n' a b c)", {"a-b", "c-"}),
        ('rm "$(pwd)/a.txt"', {"a.txt"}),
        ("rm $(basename /x/y/a.txt)", {"a.txt"}),
        ("rm $(basename a.txt.bak .bak)", {"a.txt"}),
        ("rm $(dirname src/m.py)/m.py", {"src/m.py"}),
    ]
    for cmd, want_destroys in cmds:
        imp = simulate(cmd, cwd=str(root), budget_ms=10_000)
        assert _rel_destroys(imp, root) == want_destroys, cmd
        assert imp.unknown == [], cmd


# ------------------------------------------------------------------------------
# Test 4: the algorithms match bash
# ------------------------------------------------------------------------------

def test_4_the_algorithms_match_bash():
    from demo_cli.engine import outputs

    # basename
    assert outputs._basename(["/a/b/"]) == "b\n"
    assert outputs._basename(["/"]) == "/\n"
    assert outputs._basename(["//"]) == "/\n"
    assert outputs._basename(["a.txt", ".txt"]) == "a\n"
    assert outputs._basename([".txt", ".txt"]) == ".txt\n"
    assert outputs._basename([""]) == "\n"
    assert outputs._basename(["x/y.tar.gz", ".gz"]) == "y.tar\n"

    # dirname
    assert outputs._dirname(["/a/b/"]) == "/a\n"
    assert outputs._dirname(["a"]) == ".\n"
    assert outputs._dirname(["/"]) == "/\n"
    assert outputs._dirname(["//"]) == "/\n"
    assert outputs._dirname(["a//b//"]) == "a\n"
    assert outputs._dirname([""]) == ".\n"
    assert outputs._dirname(["/a"]) == "/\n"
    assert outputs._dirname(["a", "b/c"]) == ".\nb\n"
    assert outputs._dirname(["///a"]) == "/\n"
    assert outputs._dirname(["//a"]) == "/\n"

    # printf
    assert outputs._printf(["%s\n", "a", "b", "c"]) == "a\nb\nc\n"
    assert outputs._printf(["%s-%s\n", "a", "b", "c"]) == "a-b\nc-\n"
    assert outputs._printf(["x\n", "a", "b"]) == "x\n"
    assert outputs._printf(["%s"]) == ""
    assert outputs._printf(["a%%b"]) == "a%b"

    # echo
    assert outputs._echo(["-n", "a", "b"]) == "a b"
    assert outputs._echo(["--", "a"]) == "-- a\n"
    assert outputs._echo(["-nx", "a"]) == "-nx a\n"


# ------------------------------------------------------------------------------
# Test 5: what stays unknown
# ------------------------------------------------------------------------------

def test_5_what_stays_unknown(tmp_path):
    root, _ = _setup_fixtures(tmp_path)

    cases = [
        ("rm $(cat missing.txt)", set(), ["command substitution: missing.txt does not exist"]),
        ("rm $(cat list.txt | head -1)", set(), ["command substitution: more than one command"]),
        ("rm $(git ls-files -o)", set(), ["command substitution: a command this engine does not read"]),
        ("rm $(/tmp/cat list.txt)", set(), ["command substitution: a command this engine does not read"]),
        ("cat() { echo /; }; rm -rf $(cat list.txt)", set(), ["command substitution: cat is a function defined on this line"]),
        ("function cat { echo /; }; rm $(cat list.txt)", set(), ["command substitution: cat is a function defined on this line"]),
        ("alias cat=ls; rm $(cat list.txt)", set(), ["command substitution: `alias` on this line may change what a name runs"]),
        ("PATH=/x:$PATH; rm $(cat list.txt)", set(), ["command substitution: PATH is changed on this line"]),
        ("IFS=,; rm $(cat list.txt)", set(), ["IFS is changed on this line"]),
        ("echo a.txt > l2; rm $(cat l2)", set(), ["command substitution: l2 is changed earlier on this line"]),
        ("mv list.txt l3; rm $(cat l3)", set(), ["command substitution: l3 is changed earlier on this line"]),
        ("rm $(cat list.txt) $(rm list.txt) $(cat list.txt)", {"list.txt"},
         ["command substitution: the same $( ) gives two results on this line",
          "command substitution: a command this engine does not read"]),
        ("$(echo rm) a.txt", set(), ["the command word: command substitution"]),
        ("rm $(cat ../o.txt)", set(), ["command substitution: o.txt is outside the project"]),
        ("rm $(cat opts.txt)", set(), ["an expansion that starts with '-' may be read as an option"]),
        ("rm $(cat zero.txt)", set(), ["command substitution: the output holds a NUL byte"]),
        ("rm $(cat bad.txt)", set(), ["command substitution: bad.txt is not UTF-8 text"]),
        ("rm $(cat big.txt)", set(), ["command substitution: big.txt is larger than 64 KiB"]),
        ("rm $(echo -e a.txt)", set(), ["command substitution: echo with -e or -E"]),
        ("rm $(echo 'a\\.txt')", set(), ["command substitution: echo with a backslash"]),
        ("rm $(printf '%d' 1)", set(), ["command substitution: a printf conversion this engine does not read"]),
        ("rm $(cat list.txt 2>&1)", set(), ["command substitution: a redirection inside $( )"]),
        ("cd $(cat d.txt) && rm m.py", set(), ["the working directory is unknown"]),
    ]
    for cmd, want_destroys, want_unknown in cases:
        imp = simulate(cmd, cwd=str(root), budget_ms=10_000)
        assert _rel_destroys(imp, root) == want_destroys, cmd
        assert [why for _u, why in imp.unknown] == want_unknown, cmd


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="symlink not available or Windows")
def test_5b_a_link_out_of_the_project(tmp_path):
    root, outside = _setup_fixtures(tmp_path)
    os.symlink(str(outside), str(root / "link.txt"))
    imp = simulate("rm $(cat link.txt)", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp, root) == set()
    assert [why for _u, why in imp.unknown] == ["command substitution: link.txt is outside the project"]


# ------------------------------------------------------------------------------
# Test 6: decisions
# ------------------------------------------------------------------------------

def test_6a_checkpoint_decision(tmp_path):
    root = tmp_path / "ck"
    (root / ".git" / "objects").mkdir(parents=True)
    (root / ".git" / "HEAD").write_bytes(b"ref: refs/heads/main")
    (root / "node_modules" / "left-pad").mkdir(parents=True)
    (root / "node_modules" / "left-pad" / "index.js").write_bytes(b"x" * 500)
    (root / "src" / "__pycache__").mkdir(parents=True)
    (root / "src" / "__pycache__" / "a.pyc").write_bytes(b"junk")
    (root / "src" / "app.py").write_bytes(b"print(1)")
    (root / "notes.txt").write_bytes(b"irreplaceable")
    (root / "list.txt").write_bytes(b"notes.txt\n")

    cfg = Config(project_root=str(root), mode="enforce", checkpoint={"enabled": True})
    g = Guard(cfg)
    with agent_directory(str(root)):
        r = g.evaluate("rm $(cat list.txt)", agent_id="t", session_id="t")
    assert r.decision.decision == "REVERSIBLE"
    assert r.recovery_entry is not None
    assert not r.recovery_entry["recovery_point"].endswith(".snapdir")
    assert_restores(r.recovery_entry, str(root), {"notes.txt": b"irreplaceable"})
    assert r.prediction["computed"] == [["cat list.txt", "notes.txt"]]


def test_6b_partial_capture_decision(tmp_path):
    root = tmp_path / "pc"
    root.mkdir(parents=True, exist_ok=True)
    (root / "keeper.db").write_bytes(b"k")
    (root / "extra.txt").write_bytes(b"e")
    (root / "targets.txt").write_bytes(b"extra.txt\n")

    cfg = Config(project_root=str(root), mode="enforce")
    g = Guard(cfg)
    with agent_directory(str(root)):
        r = g.evaluate("rm -f keeper.db $(cat targets.txt)", agent_id="t", session_id="t")
    assert r.decision.decision == "REVERSIBLE"
    assert r.recovery_entry is not None
    assert_restores(r.recovery_entry, str(root), {"keeper.db": b"k", "extra.txt": b"e"})


def test_6c_redirect_decision(tmp_path):
    root = tmp_path / "rd"
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.db").write_bytes(b"real data")
    (root / "name.txt").write_bytes(b"app.db\n")

    cfg = Config(project_root=str(root), mode="enforce")
    g = Guard(cfg)
    with agent_directory(str(root)):
        r = g.evaluate("echo x > $(cat name.txt)", agent_id="t", session_id="t")
    assert r.decision.decision == "REVERSIBLE"
    assert r.recovery_entry is not None
    assert_restores(r.recovery_entry, str(root), {"app.db": b"real data"})


@pytest.mark.skipif(not syscall_guard.available(), reason="syscall guard not available")
def test_6d_linux_supervisor(tmp_path):
    root = tmp_path / "ck_sup"
    (root / ".git" / "objects").mkdir(parents=True)
    (root / ".git" / "HEAD").write_bytes(b"ref: refs/heads/main")
    (root / "node_modules" / "left-pad").mkdir(parents=True)
    (root / "node_modules" / "left-pad" / "index.js").write_bytes(b"x" * 500)
    (root / "src" / "__pycache__").mkdir(parents=True)
    (root / "src" / "__pycache__" / "a.pyc").write_bytes(b"junk")
    (root / "src" / "app.py").write_bytes(b"print(1)")
    (root / "notes.txt").write_bytes(b"irreplaceable")
    (root / "list.txt").write_bytes(b"notes.txt\n")

    cfg = Config(project_root=str(root), mode="enforce")
    g = Guard(cfg)
    with agent_directory(str(root)):
        r = g.evaluate("rm $(cat list.txt)", door="agent", can_supervise=True)
    assert r.decision.decision == "REVERSIBLE"
    assert r.recovery_entry is not None
    assert_restores(r.recovery_entry, str(root), {"notes.txt": b"irreplaceable"})


# ------------------------------------------------------------------------------
# Test 7: the parser records functions
# ------------------------------------------------------------------------------

def test_7_the_parser_records_functions():
    assert parse("f() { :; }; function g { :; }; h").functions == ["f", "g"]
    assert parse("rm a.txt").functions == []


# ------------------------------------------------------------------------------
# Test 8: trailing newlines per shell
# ------------------------------------------------------------------------------

def test_8_trailing_newlines_per_shell():
    from demo_cli.engine.outputs import _finish
    cases = ["a\r\r\n", "a\r", "a\n\r\n", "a\r\n\r\n", "a\rb\n", "a.txt\r\nb.txt\r\n", "a\n\n"]
    assert [_finish(c, windows=False) for c in cases] == ["a\r\r", "a\r", "a\n\r", "a\r\n\r", "a\rb", "a.txt\r\nb.txt\r", "a"]
    assert [_finish(c, windows=True) for c in cases] == ["a\r", "a\r", "a", "a", "a\rb", "a.txt\r\nb.txt", "a"]

