"""M2.2e: the shell guard's prefilter is generated from the rule tables.

Before: a hand-typed glob list (rm, mv, cp, find, >, DROP ...) plus git's
generated globs, so `kubectl delete`, `aws s3 rm`, `systemctl stop`,
`crontab x` typed in a shell (Claude Code `!` mode, a terminal) never reached
guard-shell. Now every command word a rule covers - lazy families and the
wrappers that can carry one included - is a table the trap looks the first
command word up in (an associative array on bash 4+, a word list on bash 3).
One glob per tool cost ~3 ms per command; the lookup adds ~0.1 ms (measured
2026-10-08), and git keeps its own generated globs so `git status` costs
nothing.
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest

from demo_cli.engine.rules import LAZY_FAMILIES, READ_ONLY, RULES, SHELLS
from test_shell_guard import BASH, _fake_demo_cli, _write_sh


def test_1_the_words_come_from_the_tables():
    from demo_cli.classify import _WRAPPERS
    from demo_cli.engine.rules import shell_prefilter_words
    words = set(shell_prefilter_words())
    covered = (set(LAZY_FAMILIES) | {t for r in RULES for t in r.tools}) - {"git"}
    # M2.2f: the interpreters a rule claims only narrowly (python manage.py)
    # stay out: sending every `python x.py` to guard-shell is M2.3's call
    runners = {"python", "python3", "py",
               "awk", "mawk", "nawk"}       # M2.3a: in nearly every typed pipeline; gawk stays
    assert covered - READ_ONLY - SHELLS - runners <= words
    assert not words & runners
    assert set(_WRAPPERS) <= words
    assert not words & READ_ONLY and not words & SHELLS and "git" not in words
    for tool in ("kubectl", "aws", "terraform", "docker", "systemctl", "crontab", "kill",
                 "npm", "curl", "heroku", "stripe", "reg", "taskkill", "sudo"):
        assert tool in words, tool


def test_2_the_snippet_carries_every_word_and_no_placeholder():
    from demo_cli.cli import _SHELL_GUARD_SNIPPET
    from demo_cli.engine.rules import shell_prefilter_words
    from demo_cli.classify import git_prefilter_globs
    assert "__DEMO_CLI_" not in _SHELL_GUARD_SNIPPET
    for word in shell_prefilter_words():
        assert f"[{word}]=1" in _SHELL_GUARD_SNIPPET, word
        assert f" {word} " in _SHELL_GUARD_SNIPPET, word          # the bash 3 list
    for glob in git_prefilter_globs():
        assert glob in _SHELL_GUARD_SNIPPET, glob


def test_3_importing_the_cli_does_not_build_it(tmp_path):
    """Every demo_cli call imports cli.py: the snippet (and every rule family
    it names) is built on first use only."""
    code = ("import sys\n"
            "import demo_cli.cli as c\n"
            "print('built' if '_SHELL_GUARD_SNIPPET' in vars(c) else 'lazy')\n"
            "print(sorted(m for m in sys.modules if m.startswith('demo_cli.engine.rules_')))\n")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    out = subprocess.run([sys.executable, "-c", code], cwd=str(tmp_path), env=env,
                         capture_output=True, text=True, timeout=120).stdout.splitlines()
    assert out == ["lazy", "[]"]


LOGGING = '#!/bin/sh\n[ "$1" = guard-shell ] && printf "%s\\n" "$2" >> "$GUARD_LOG"\nexit 0\n'


@pytest.mark.skipif(BASH is None, reason="no bash for this platform "
                                         "(WSL's bash is not Windows)")
def test_4_which_commands_reach_guard_shell(tmp_path):
    """A real bash with the real snippet and a stub demo_cli that only logs."""
    from demo_cli.cli import _SHELL_GUARD_SNIPPET
    binn = tmp_path / "bin"
    binn.mkdir()
    _fake_demo_cli(str(binn), LOGGING)
    script = _write_sh(str(tmp_path / "guard.sh"), _SHELL_GUARD_SNIPPET)
    log = tmp_path / "calls.log"
    lines = [
        "kubectl delete pod x 2>/dev/null",     # a lazy family
        "X=1 systemctl --version 2>/dev/null",  # past a prefix assignment
        "sudo -n true 2>/dev/null",             # a wrapper
        "/usr/bin/crontab -l 2>/dev/null",      # a path
        "taskkill.exe /? 2>/dev/null",          # Git Bash: .exe
        "true",                                  # nothing below may call it
        "echo kubectl",
        "ls >/dev/null",
        "v=\"aws s3 rm\"",
        "git status 2>/dev/null",
    ]
    body = _write_sh(str(tmp_path / "cmds.sh"), "\n".join(lines) + "\n")
    env = dict(os.environ, PATH=f"{binn}{os.pathsep}" + os.environ["PATH"],
               BASH_ENV=str(script), GUARD_LOG=str(log))
    subprocess.run([BASH, body], env=env, capture_output=True, text=True, timeout=60)
    called = log.read_text().splitlines() if log.exists() else []
    firsts = [c.split()[0] for c in called]
    assert firsts == ["kubectl", "X=1", "sudo", "/usr/bin/crontab", "taskkill.exe"], called
