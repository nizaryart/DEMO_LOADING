"""V22 (found in the red-team notes, R3; reproduced 2026-10-09): deleting an
in-project symbolic link was captured REVERSIBLE, but undo brought the link
back as a regular file. snapshot() records the link; snapshot_set() wraps a
single target in a group entry labelled with the target's kind, and
restore_entry() restored that wrapper - not the member holding the link.
Undo now restores the members of any entry that has them."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from demo_cli.config import Config
from demo_cli.guard import Guard, agent_directory
from demo_cli.recovery import restore_entry


def _symlink_or_skip(src: Path, link: Path) -> None:
    try:
        os.symlink(src, link)
    except (OSError, NotImplementedError) as e:
        pytest.skip(f"this system refuses to create a symbolic link ({e})")


def _project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "inside.txt").write_text("INSIDE\n")
    (proj / "plain.txt").write_text("PLAIN\n")
    return proj


def _eval(proj: Path, command: str):
    with agent_directory(str(proj)):
        return Guard(config=Config(project_root=str(proj), mode="enforce")).evaluate(command, door="agent")


def test_1_a_deleted_symlink_comes_back_as_a_symlink(tmp_path):
    proj = _project(tmp_path)
    _symlink_or_skip(proj / "inside.txt", proj / "link.txt")
    r = _eval(proj, "rm link.txt")
    assert (r.decision.decision, r.recovery_entry is not None) == ("REVERSIBLE", True)
    os.unlink(proj / "link.txt")                         # what `rm` does
    assert restore_entry(r.recovery_entry) is True
    assert os.path.islink(proj / "link.txt")
    # The same target - Windows may spell it with its \\?\ prefix.
    assert os.path.samefile(proj / "link.txt", proj / "inside.txt")
    assert (proj / "inside.txt").read_text() == "INSIDE\n"


def test_2_control_a_plain_file_still_comes_back(tmp_path):
    proj = _project(tmp_path)
    r = _eval(proj, "rm plain.txt")
    assert (r.decision.decision, r.recovery_entry is not None) == ("REVERSIBLE", True)
    os.unlink(proj / "plain.txt")
    assert restore_entry(r.recovery_entry) is True
    assert (os.path.islink(proj / "plain.txt"), (proj / "plain.txt").read_text()) == (False, "PLAIN\n")


def test_3_control_a_truncation_through_a_link_restores_the_target(tmp_path):
    proj = _project(tmp_path)
    _symlink_or_skip(proj / "inside.txt", proj / "link.txt")
    r = _eval(proj, "echo x > link.txt")
    assert (r.decision.decision, r.recovery_entry is not None) == ("REVERSIBLE", True)
    (proj / "inside.txt").write_text("x\n")              # what the redirect does
    assert restore_entry(r.recovery_entry) is True
    assert os.path.islink(proj / "link.txt")
    assert (proj / "inside.txt").read_text() == "INSIDE\n"
