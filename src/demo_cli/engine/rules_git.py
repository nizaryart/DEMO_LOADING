"""The git family: one rule, loaded only when a line names git (M2.2a).

The grammar and the examples live here, as rules_sql.py does for the SQL
clients; the work is in git_ops.py. A hook call that never meets git pays
nothing for either.
"""
from __future__ import annotations

from typing import Tuple

from .effects import LATER
from .rules import OptionSpec, Rule, ex

FAMILY_RULES: Tuple[Rule, ...] = (
    Rule(id="git", tools=("git",), resolver="git", options=OptionSpec(),
         examples=(
             ex("git status", note="a read"),
             ex("git log", note="a read"),
             ex("git push origin main", remote=True,
                note="only adds: allowed and listed"),
             ex("git push origin +main", remote=True,
                note="a forced update: a surface no local copy restores"),
             ex("git push --delete origin feat", remote=True),
             ex("git rm a.txt", destroys={"a.txt"},
                note="the file leaves the working tree, so it is captured"),
             ex("git rm --cached a.txt", note="the index only: the file stays"),
             ex("git mv a.txt b.txt",
                note="VERIFIED: without -f git mv refuses an existing destination"),
             ex("git branch -D feat", remote=True,
                note="ruling (c): the reflog brings it back, so it is listed"),
             ex("git config --global x y", note="a key git never runs: nothing to undo"),
             # M2.2d: keys whose value git runs (rulings D1-D2)
             ex("git config core.hooksPath /tmp/h", reaches={"later:git-config@local": LATER}),
             ex("git config --global alias.st '!rm -rf ~'",
                reaches={"later:git-config@global": LATER}),
             ex("git config set --global core.pager 'sh evil.sh'",
                reaches={"later:git-config@global": LATER}, note="the subcommand form"),
             ex("git config --glob filter.x.smudge 'sh x'",
                reaches={"later:git-config@global": LATER},
                note="parse-options: a unique prefix is the option"),
             ex("git config --get core.pager", note="a read"),
             ex("git config core.pager", note="no value: a read"),
             ex("git config --unset core.hooksPath", note="takes a setting away"),
             ex("git -c core.pager='rm -rf ~' log", unknown=True,
                note="runs now, unread: today's path decides"),
             ex("git --exec-path=/tmp/evil status", unknown=True),
             ex("git -C sub status", note="a global option before the subcommand"),
             ex("git frobnicate x", uncovered={"git frobnicate"},
                note="an unlisted subcommand is uncovered, so today's path decides"),
         )),
)
