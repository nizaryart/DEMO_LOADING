"""Every claim in engine/rules_powershell.py, run as a test (C3).

The POSIX rule table's examples run in tests/test_engine_rules.py; this is
the PowerShell counterpart. Each example runs the whole PowerShell path -
parse, bind, simulate - in the fixture below and must produce exactly the
impact it declares. A family's negative examples (nothing destroyed) are
asserted beside its first positive example, their control: a harness that saw
nothing would pass every negative alone.
"""
import os

import pytest

from demo_cli.config import Config
from demo_cli.engine import predict
from demo_cli.engine.rules_powershell import PS_FAMILIES, all_examples

SEMANTIC_BUDGET_MS = 10_000        # meaning, not speed (as in test_engine_rules)

FIXTURE = {"a.txt": "AAA\n", "b.txt": "BBB\n", "log.txt": "LOG\n", "notes.md": "N\n",
           "dist/out.o": "OBJ\n", "t1.tmp": "T1\n", "t2.tmp": "T2\n"}


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
        imp = predict(command, Config(project_root=str(root)), budget_ms=SEMANTIC_BUDGET_MS,
                      dialect="powershell").impact
    finally:
        os.chdir(here)

    def rel(p, is_dir=False):
        return os.path.relpath(p, str(root)).replace(os.sep, "/") + ("/" if is_dir else "")
    return ({rel(p, p in imp.destroyed_dirs) for p in imp.destroys},
            {rel(p) for p in imp.creates}, {rel(p) for p in imp.changes}, bool(imp.unknown))


def _want(ex):
    return set(ex.destroys), set(ex.creates), set(ex.changes), ex.unknown


def _positive(ex):
    return bool(ex.destroys or ex.creates or ex.changes or ex.unknown)


CASES = all_examples()


@pytest.mark.parametrize("family,example", CASES,
                         ids=[f"{f}:{e.command[:40]}" for f, e in CASES])
def test_a_cmdlet_claim_produces_the_impact_it_declares(tmp_path, family, example):
    root = _fixture(tmp_path)
    positives = [e for e in PS_FAMILIES[family] if _positive(e)]
    if positives and example is not positives[0]:
        control = positives[0]
        assert _impact(root, control.command) == _want(control), \
            f"control ({control.command!r}): the harness sees this family act"
        root = _fixture(tmp_path / "again")
    assert _impact(root, example.command) == _want(example), example.note


def test_every_family_carries_examples():
    for family, examples in PS_FAMILIES.items():
        assert examples, f"{family}: a cmdlet with no example is a cmdlet nobody pinned"
