import argparse
import os
import sys
import pytest

from demo_cli.config import Config
from demo_cli.recovery import Target, snapshot, snapshot_set, load_entries
from demo_cli.syscall_guard import run_supervised, available
from demo_cli.cli import cmd_undo
from demo_cli import render


@pytest.mark.skipif(not available(), reason="Linux x86-64 ptrace required")
def test_supervised_run_deletes_3_files_single_group_restores_all(tmp_path):
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    rec_dir = cfg.recovery_dir

    f1 = tmp_path / "f1.txt"
    f2 = tmp_path / "f2.txt"
    f3 = tmp_path / "f3.txt"
    f1.write_text("content 1")
    f2.write_text("content 2")
    f3.write_text("content 3")

    cmd = ["bash", "-c", f"rm '{f1}' '{f2}' '{f3}'"]
    rc = run_supervised(cmd, config=cfg)
    assert rc == 0
    assert not f1.exists()
    assert not f2.exists()
    assert not f3.exists()

    entries = load_entries(rec_dir)
    assert len(entries) == 3
    groups = {e.get("group") for e in entries}
    assert len(groups) == 1
    group_id = list(groups)[0]
    assert group_id is not None

    # Undo using group_id
    args = argparse.Namespace(id=group_id, root=str(tmp_path), target=None, no_presnapshot=False)
    undo_rc = cmd_undo(args)
    assert undo_rc == 0

    assert f1.read_text() == "content 1"
    assert f2.read_text() == "content 2"
    assert f3.read_text() == "content 3"


def test_snapshot_set_all_or_nothing(tmp_path):
    rec_dir = str(tmp_path / ".demo_cli" / "recovery")
    f1 = tmp_path / "ok1.txt"
    f2 = tmp_path / "missing.txt"
    f3 = tmp_path / "ok2.txt"
    f1.write_text("ok1")
    f3.write_text("ok2")

    targets = [
        Target("file", str(f1), "f1"),
        Target("file", str(f2), "f2"),
        Target("file", str(f3), "f3"),
    ]

    res = snapshot_set(targets, rec_dir, strategy="snapshot")
    assert res is None

    # Undo offers no partial recovery
    entries = load_entries(rec_dir)
    assert len(entries) == 0

    args = argparse.Namespace(id=None, root=str(tmp_path), target=None, no_presnapshot=False)
    assert cmd_undo(args) == 1


def test_old_entry_without_group_undoes_as_before(tmp_path):
    rec_dir = str(tmp_path / ".demo_cli" / "recovery")
    f = tmp_path / "old.txt"
    f.write_text("original content")

    e = snapshot(Target("file", str(f), "old"), rec_dir, strategy="snapshot")
    assert e is not None
    # Simulate an old index entry without a 'group' field
    idx_path = os.path.join(rec_dir, "index.jsonl")
    lines = open(idx_path).readlines()
    import json
    parsed = json.loads(lines[-1])
    parsed.pop("group", None)
    with open(idx_path, "w") as out_f:
        out_f.write(json.dumps(parsed) + "\n")

    f.write_text("mutated content")
    args = argparse.Namespace(id=e["id"], root=str(tmp_path), target=None, no_presnapshot=False)
    assert cmd_undo(args) == 0
    assert f.read_text() == "original content"


def test_demo_cli_log_collapses_group_into_one_line(tmp_path, capsys):
    rec_dir = str(tmp_path / ".demo_cli" / "recovery")
    f1 = tmp_path / "a.txt"
    f2 = tmp_path / "b.txt"
    f3 = tmp_path / "c.txt"
    f1.write_text("a")
    f2.write_text("b")
    f3.write_text("c")

    targets = [
        Target("file", str(f1), "a"),
        Target("file", str(f2), "b"),
        Target("file", str(f3), "c"),
    ]
    res = snapshot_set(targets, rec_dir, strategy="snapshot", action="rm items")
    assert res is not None

    entries = load_entries(rec_dir)
    assert len(entries) == 3

    render.set_color(False)
    render.render_log(entries, "test")
    out = capsys.readouterr().out

    group_prefix = res["group"][:8]
    matching_lines = [l for l in out.splitlines() if group_prefix in l]
    assert len(matching_lines) == 1
    assert "group" in matching_lines[0]
    assert "(3 files)" in matching_lines[0]

