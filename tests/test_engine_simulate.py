"""The shadow engine's simulation semantics (Part B, 2026-09-27).

Run with a TEST-ONLY rule table that adds touch (CREATE) and mv (MOVE) to
the production families, so the semantics - separators, cwd, subshells,
variables, globs, content origin - are proven now, before those families
ship in C. Each negative sits beside a control that shows the same harness
does see the effect.
"""
import os

import pytest

from demo_cli.config import Config
from demo_cli.engine import predict
from demo_cli.engine.invocation import parse_options
from demo_cli.engine.rules import TEST_ONLY_RULES, OptionSpec
from demo_cli.engine.simulate import BudgetExceeded
from demo_cli.model import parse


# These tests pin MEANING, not speed. The production budget
# (engine.BUDGET_MS, 10 ms) is wall-clock: under machine load an example
# overran it and failed for a reason unrelated to what it asserts (review
# 2026-09-28). The budget itself is tested deterministically, with a clock
# that jumps, in test_engine_simulate.py and test_engine_inert.py.
SEMANTIC_BUDGET_MS = 10_000


class _SlowClock:
    """Every reading is an hour after the last: a forced slow step, so running
    over the budget is certain rather than a matter of machine load."""

    def __init__(self):
        self.t = 0.0

    def perf_counter(self):
        self.t += 3600.0
        return self.t

    # B0 (msg 037): the budget now reads the CPU clock too.
    def process_time(self):
        return self.perf_counter()


@pytest.fixture
def root(tmp_path):
    for rel in ("a.txt", "b.txt", "dir/d.txt", "dir/e.txt", "list.txt"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
    return tmp_path


def sim(root, command):
    here = os.getcwd()
    os.chdir(str(root))
    try:
        imp = predict(command, Config(project_root=str(root)), rules=TEST_ONLY_RULES,
                      budget_ms=SEMANTIC_BUDGET_MS).impact
    finally:
        os.chdir(here)
    rel = lambda p: os.path.relpath(p, str(root))          # noqa: E731
    return {rel(p) for p in imp.destroys}, {rel(p) for p in imp.creates}, imp


# (command, what it destroys) - each row's neighbour is its control
PAIRS = [
    # CREATE only where nothing exists (review correction 2)
    ("touch new.txt && rm new.txt", set(), "rm a.txt", {"a.txt"}),
    ("touch a.txt && rm a.txt", {"a.txt"}, "touch new.txt && rm new.txt", set()),
    ("> a.txt; rm a.txt", {"a.txt"}, "> new.txt; rm new.txt", set()),
    # content origin through a move
    ("mv a.txt b.txt && rm b.txt", {"a.txt", "b.txt"}, "mv a.txt new.txt", set()),
    ("mv a.txt dir/ && rm -rf dir", {"a.txt", "dir"}, "rm -rf dir", {"dir"}),
    ("mv dir moved && rm moved/d.txt", {os.path.join("dir", "d.txt")}, "mv dir moved", set()),
    # && runs on success, || on failure
    ("true || rm a.txt", set(), "false || rm a.txt", {"a.txt"}),
    ("false && rm a.txt", set(), "true && rm a.txt", {"a.txt"}),
    ("mv a.txt new.txt || rm a.txt", {"a.txt"}, "mv a.txt new.txt && rm a.txt", set()),
    # cd: into a directory that exists succeeds; a missing one fails
    ("cd missing && rm a.txt", set(), "cd missing; rm a.txt", {"a.txt"}),
    ("cd dir && rm d.txt", {os.path.join("dir", "d.txt")}, "cd dir && rm a.txt", set()),
    # subshells and pipelines keep their cwd to themselves
    ("(cd dir; rm d.txt); rm e.txt", {os.path.join("dir", "d.txt")},
     "cd dir; rm d.txt; rm e.txt", {os.path.join("dir", "d.txt"), os.path.join("dir", "e.txt")}),
    ("bash -c 'cd dir' ; rm d.txt", set(), "cd dir ; rm d.txt", {os.path.join("dir", "d.txt")}),
    ("cd dir | rm d.txt", set(), "cd dir && rm d.txt", {os.path.join("dir", "d.txt")}),
    # variables on words
    ("rm '$X'", set(), "X=a.txt; rm $X", {"a.txt"}),
    ("X='a.txt b.txt'; rm \"$X\"", set(), "X='a.txt b.txt'; rm $X", {"a.txt", "b.txt"}),
    # globs see the simulated filesystem
    ("touch dir/new.txt && rm dir/*.txt",
     {os.path.join("dir", "d.txt"), os.path.join("dir", "e.txt")},
     "rm dir/*.md", set()),
]


@pytest.mark.parametrize("command,destroys,control,control_destroys", PAIRS,
                         ids=[p[0][:40] for p in PAIRS])
def test_simulation(root, command, destroys, control, control_destroys):
    assert sim(root, control)[0] == control_destroys, f"control: {control!r}"
    assert sim(root, command)[0] == destroys


def test_created_then_deleted_destroys_nothing(root):
    """`creates` means MAY exist, new, at the end - if the rm fails, new.txt
    stays - so only `destroys` is asserted for the pair."""
    assert sim(root, "touch new.txt")[1] == {"new.txt"}, "control: touch creates"
    assert sim(root, "touch a.txt && rm a.txt")[0] == {"a.txt"}, "control: a real file is lost"
    assert sim(root, "touch new.txt && rm new.txt")[0] == set()


def test_what_cannot_be_resolved_is_unknown_never_guessed(root):
    assert not sim(root, "X=a.txt; rm $X")[2].unknown, "control: a same-line value is known"
    for command in ("X=$(cat list.txt); rm $X", "rm $UNSET", "for f in a b; do rm $f; done",
                    "rm $(cat list.txt)", "cd $SOMEWHERE && rm a.txt"):
        destroys, _c, imp = sim(root, command)
        assert imp.unknown, command
        assert destroys == set(), command


def test_the_filesystem_is_never_written(root):
    before = sorted(str(p) for p in root.rglob("*"))
    sim(root, "rm -rf dir; echo x > a.txt; touch z; mv b.txt c.txt")
    assert sorted(str(p) for p in root.rglob("*")) == before


# ---- option parsing ------------------------------------------------------

SPEC = OptionSpec(flags={"-r": "recursive", "-f": "force", "--force": "force",
                         "--interactive": "prompt"},
                  values={"-t": "target", "--target-directory": "target"})


def _parse(line):
    return parse_options(parse(line).commands[0].argv[1:], SPEC)


def test_option_parsing():
    p = _parse("x -rf a")
    assert p.flags == {"recursive", "force"} and [w.value for w in p.operands] == ["a"]
    p = _parse("x a -f --interactive=never")
    assert p.flags == {"force", "prompt"}, "GNU permutation and --opt=value"
    p = _parse("x -- -f")
    assert not p.flags and [w.value for w in p.operands] == ["-f"]
    p = _parse("x -tdest a --target-directory other")
    assert [w.value for w in p.options["target"]] == ["dest", "other"]
    p = _parse("x -z --weird a")
    assert p.unknown_options == ["-z", "--weird"], "unknown options are kept, not dropped"
    assert _parse("x a --help").early_flags == frozenset(), "control: nothing before a"
    assert "force" in _parse("x -f a").early_flags


def test_the_budget_stops_the_simulation(root, monkeypatch):
    """Deterministic: a clock that jumps an hour per reading. The same clock
    and a budget longer than every jump pass - the control - and the
    production budget (engine.BUDGET_MS) raises."""
    import demo_cli.engine.simulate as simulate
    here = os.getcwd()
    os.chdir(str(root))
    try:
        monkeypatch.setattr(simulate, "time", _SlowClock())
        predict("rm a.txt", Config(project_root=str(root)), budget_ms=1e12)     # control
        with pytest.raises(BudgetExceeded):
            predict("rm a.txt", Config(project_root=str(root)))
    finally:
        os.chdir(here)
