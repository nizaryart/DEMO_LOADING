"""V17 (found by the analysis worker, A5; reproduced by ORCH, 2026-10-08): with
checkpoints enabled, a line the engine cannot read whose operand lies OUTSIDE
the project took a whole-project checkpoint and came back REVERSIBLE - but the
checkpoint holds only the project, so the outside file was not recoverable.
Such a line now escalates; the same line inside the project still gets its
checkpoint."""
from __future__ import annotations

from pathlib import Path

from demo_cli.config import Config
from demo_cli.guard import Guard, agent_directory


def _guard(proj: Path, checkpoints: bool) -> Guard:
    cfg = Config(project_root=str(proj), mode="enforce")
    cfg.checkpoint = {"enabled": checkpoints}
    return Guard(config=cfg)


def _layout(tmp_path: Path):
    proj, outside = tmp_path / "proj", tmp_path / "outside"
    proj.mkdir()
    outside.mkdir()
    (proj / "app.py").write_text("x\n")
    (proj / "temp.txt").write_text("t\n")
    victim = outside / "victim.txt"
    victim.write_text("critical\n")
    return proj, victim


def test_1_an_outside_operand_is_never_covered_by_a_project_checkpoint(tmp_path: Path):
    proj, victim = _layout(tmp_path)
    for can_supervise in (False, True):
        with agent_directory(str(proj)):
            r = _guard(proj, True).evaluate(f"rm -f {victim.as_posix()} $(date +%s)",
                                            door="agent", can_supervise=can_supervise)
        assert (r.decision.decision, r.recovery_entry) == ("ESCALATE", None), can_supervise
    assert victim.read_text() == "critical\n"


def test_2_inside_the_project_the_checkpoint_still_covers_it(tmp_path: Path):
    proj, _victim = _layout(tmp_path)
    with agent_directory(str(proj)):
        r = _guard(proj, True).evaluate(f"rm -f {(proj / 'temp.txt').as_posix()} $(date +%s)",
                                        door="agent", can_supervise=False)
    assert r.decision.decision == "REVERSIBLE"
    assert r.recovery_entry is not None
    assert "whole-workspace checkpoint" in r.decision.reason


def test_3_with_checkpoints_off_nothing_changes(tmp_path: Path):
    proj, victim = _layout(tmp_path)
    with agent_directory(str(proj)):
        r = _guard(proj, False).evaluate(f"rm -f {victim.as_posix()} $(date +%s)",
                                         door="agent", can_supervise=False)
    assert (r.decision.decision, r.recovery_entry) == ("ESCALATE", None)
