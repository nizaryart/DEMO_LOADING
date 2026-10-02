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

try:                                    # C2a on: lazy families (the SQL clients) too
    from demo_cli.engine.rules import all_rules
    RULES = all_rules()
except ImportError:                     # the previous tree, for fail-on-old
    pass

# These tests pin MEANING, not speed. The production budget
# (engine.BUDGET_MS, 10 ms) is wall-clock: under machine load an example
# overran it and failed for a reason unrelated to what it asserts (review
# 2026-09-28). The budget itself is tested deterministically, with a clock
# that jumps, in test_engine_simulate.py and test_engine_inert.py.
SEMANTIC_BUDGET_MS = 10_000

FIXTURE = {"a.txt": "a", "b.txt": "b", "-f": "f", "dir/d.txt": "d", "dir/e.txt": "e",
           "sub/c.txt": "c", "list.txt": "a.txt\n",
           # Part C1
           "src/app.js": "js", "main.go": "go", "x.txt": "x", "x.txt~": "old backup",
           "x.txt.bak": "old backup",
           # Part C2a: the engine never opens a database, so app.db's bytes do not matter
           "app.db": "sqlite", "q.sql": "DELETE FROM t;\n", "r.sql": "SELECT 1;\n"}


def _zips(root):
    import zipfile
    with zipfile.ZipFile(str(root / "m.zip"), "w") as z:
        z.writestr("a.txt", "from the zip")
        z.writestr("new.txt", "from the zip")
    with zipfile.ZipFile(str(root / "zs.zip"), "w") as z:
        z.writestr("../evil.txt", "escapes")                  # zip-slip
    with zipfile.ZipFile(str(root / "sl.zip"), "w") as z:
        info = zipfile.ZipInfo("link")
        info.external_attr = (0o120777 << 16)                # a symbolic link member
        z.writestr(info, "a.txt")


def _fixture(root):
    for rel, text in FIXTURE.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    (root / "emptydir").mkdir()
    _zips(root)
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
        return os.path.relpath(p, str(root)).replace(os.sep, "/") + ("/" if is_dir else "")
    return ({rel(p, p in imp.destroyed_dirs) for p in imp.destroys},
            {rel(p) for p in imp.creates}, {rel(p) for p in imp.changes}, bool(imp.unknown),
            bool(imp.remote), dict(imp.databases), set(imp.no_capture)), \
        (set(imp.uncovered), dict(imp.remote))


def _want(ex):
    return (set(ex.destroys), set(ex.creates), set(ex.changes), ex.unknown, ex.remote,
            ex.databases, set(ex.no_capture))


def _positive(ex):
    return bool(ex.destroys or ex.creates or ex.changes or ex.unknown or ex.remote
                or ex.databases or ex.no_capture)


FAMILIES = [(r.id, r.examples) for r in RULES] + [("redirect", REDIRECT_EXAMPLES)]
CASES = [(fam, ex) for fam, examples in FAMILIES for ex in examples]


@pytest.mark.parametrize("family,example", CASES,
                         ids=[f"{f}:{e.command[:40]}" for f, e in CASES])
def test_a_rule_example_produces_the_impact_it_declares(tmp_path, family, example):
    if os.name == "nt" and getattr(example, "posix_only", False):
        pytest.skip("no block devices under /dev on Windows")
    root = _fixture(tmp_path)
    control = next(e for f, examples in FAMILIES if f == family for e in examples if _positive(e))
    if example is not control:
        assert _impact(root, control.command)[0] == _want(control), \
            f"control ({control.command!r}): the harness sees this family act"
    got, (uncovered, reaches) = _impact(root, example.command)
    assert got == _want(example), example.note
    assert set(example.uncovered) <= uncovered, "the part not modelled is reported"
    if example.reaches is not None:
        assert reaches == example.reaches, "the remote surfaces and their kinds (C2)"


def test_every_rule_carries_examples_and_at_least_one_that_acts():
    for family, examples in FAMILIES:
        assert examples, f"{family}: a rule without examples is untested"
        assert any(_positive(e) for e in examples), f"{family}: no positive example"
    for rule in RULES:
        assert rule.options is not None and (rule.effects or rule.resolver), rule.id
