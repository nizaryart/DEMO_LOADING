"""The rule table's examples, run as tests (Part B, 2026-09-27).

Every Example in engine/rules.py runs the whole shadow pipeline - parse,
Invocation, rules, simulation - in the fixture below and must produce exactly
the impact it declares. A rule's negative examples (nothing destroyed) are
asserted beside its first positive example, which is their control: a
harness that saw nothing would pass every negative alone.
"""
import os

import pytest

from demo_cli.config import Config
from demo_cli.engine import predict
from demo_cli.engine.rules import REDIRECT_EXAMPLES, RULES

# These tests pin MEANING, not speed. The production budget
# (engine.BUDGET_MS, 10 ms) is wall-clock: under machine load an example
# overran it and failed for a reason unrelated to what it asserts (review
# 2026-09-28). The budget itself is tested deterministically, with a clock
# that jumps, in test_engine_simulate.py and test_engine_inert.py.
SEMANTIC_BUDGET_MS = 10_000

FIXTURE = {"a.txt": "a", "b.txt": "b", "-f": "f", "dir/d.txt": "d", "dir/e.txt": "e",
           "sub/c.txt": "c", "list.txt": "a.txt\n"}


def _fixture(root):
    for rel, text in FIXTURE.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    (root / "emptydir").mkdir()
    return root


def _impact(root, command):
    here = os.getcwd()
    os.chdir(str(root))
    try:
        imp = predict(command, Config(project_root=str(root)),
                      budget_ms=SEMANTIC_BUDGET_MS).impact
    finally:
        os.chdir(here)

    def rel(p, is_dir=False):
        return os.path.relpath(p, str(root)) + ("/" if is_dir else "")
    return ({rel(p, p in imp.destroyed_dirs) for p in imp.destroys},
            {rel(p) for p in imp.creates}, {rel(p) for p in imp.changes}, bool(imp.unknown))


def _want(ex):
    return (set(ex.destroys), set(ex.creates), set(ex.changes), ex.unknown)


def _positive(ex):
    return bool(ex.destroys or ex.creates or ex.changes or ex.unknown)


FAMILIES = [(r.id, r.examples) for r in RULES] + [("redirect", REDIRECT_EXAMPLES)]
CASES = [(fam, ex) for fam, examples in FAMILIES for ex in examples]


@pytest.mark.parametrize("family,example", CASES,
                         ids=[f"{f}:{e.command[:40]}" for f, e in CASES])
def test_a_rule_example_produces_the_impact_it_declares(tmp_path, family, example):
    root = _fixture(tmp_path)
    control = next(e for f, examples in FAMILIES if f == family for e in examples if _positive(e))
    if example is not control:
        assert _impact(root, control.command) == _want(control), \
            f"control ({control.command!r}): the harness sees this family act"
    assert _impact(root, example.command) == _want(example), example.note


def test_every_rule_carries_examples_and_at_least_one_that_acts():
    for family, examples in FAMILIES:
        assert examples, f"{family}: a rule without examples is untested"
        assert any(_positive(e) for e in examples), f"{family}: no positive example"
    for rule in RULES:
        assert rule.options is not None and rule.effects, rule.id
