"""V18 step 2 (ruling 2026-10-09: record outside destroys, no block; receipts
only, Nizar 2026-10-10): the Linux syscall guard backs up what unread code
destroys inside the project, and outside the project it captured nothing and
recorded nothing. Each existing file a destructive syscall reaches outside
the project is now RECORDED - one receipt per file per run, never backed up,
never blocked; temp and pseudo filesystems are skipped; a run is capped."""
from __future__ import annotations

import os
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="syscall guard requires Linux (ptrace)")

from demo_cli import recovery, syscall_guard        # noqa: E402
from demo_cli.config import Config                  # noqa: E402
from demo_cli.receipts import load_receipts, verify_chain  # noqa: E402


def _dirs(tmp_path):
    proj, out = tmp_path / "proj", tmp_path / "outside"
    proj.mkdir()
    out.mkdir()
    return proj, out


def _run(script, proj, monkeypatch, deny=False, temp_skipped=False):
    # Hermetic: an installed shell guard must not re-fire inside `bash -c`.
    monkeypatch.delenv("BASH_ENV", raising=False)
    monkeypatch.chdir(proj)
    if not temp_skipped:
        # tmp_path lives under the temp dir, which the record skips; these
        # tests stand in for a home directory.
        monkeypatch.setattr(syscall_guard, "_temp_roots", lambda: [], raising=False)
    cfg = Config(project_root=str(proj))
    rc = syscall_guard.run_supervised(["bash", "-c", script], config=cfg, deny=deny)
    return cfg, rc


def _outside(cfg):
    return [r for r in load_receipts(cfg.receipts_path)
            if (r.get("matched_rule") or "").startswith("sys_outside")]


def test_1_an_outside_delete_is_recorded_not_backed_up_and_inside_is_unchanged(tmp_path, monkeypatch):
    proj, out = _dirs(tmp_path)
    (out / "notes.txt").write_text("OUT\n")
    (proj / "data.txt").write_text("IN\n")
    cfg, rc = _run(f"rm -f {out / 'notes.txt'} data.txt", proj, monkeypatch)
    assert rc == 0
    assert (os.path.exists(out / "notes.txt"), os.path.exists(proj / "data.txt")) == (False, False)
    rows = _outside(cfg)
    assert len(rows) == 1
    r = rows[0]
    # coreutils rm removes through unlinkat (since coreutils 8.0).
    assert (r["matched_rule"], r["action_raw"]) == (
        "sys_outside_unlinkat", f"[syscall] unlinkat {out / 'notes.txt'}")
    assert (r["decision"], r["recovery_point"], r["classification"]) == ("ALLOW", None, "destructive")
    assert "recorded, not backed up, cannot be undone" in r["reason"]
    # Inside the project: the backup and undo are untouched.
    entries = recovery.load_entries(cfg.recovery_dir)
    assert len(entries) == 1
    assert recovery.restore_entry(entries[0]) is True
    assert (proj / "data.txt").read_text() == "IN\n"
    assert not os.path.exists(out / "notes.txt")
    assert verify_chain(cfg.receipts_path).ok is True


def test_2_never_blocked_even_when_the_guard_blocks_inside(tmp_path, monkeypatch):
    proj, out = _dirs(tmp_path)
    (out / "notes.txt").write_text("OUT\n")
    (proj / "data.txt").write_text("IN\n")
    cfg, _ = _run(f"rm -f {out / 'notes.txt'} data.txt", proj, monkeypatch, deny=True)
    assert (os.path.exists(out / "notes.txt"), (proj / "data.txt").read_text()) == (False, "IN\n")
    assert len(_outside(cfg)) == 1


def test_3_a_truncation_through_an_inside_link_records_the_outside_target(tmp_path, monkeypatch):
    proj, out = _dirs(tmp_path)
    (out / "conf.ini").write_text("KEEP\n")
    try:
        os.symlink(out / "conf.ini", proj / "conf.ini")
    except (OSError, NotImplementedError) as e:
        pytest.skip(f"this system refuses to create a symbolic link ({e})")
    cfg, _ = _run("echo x > conf.ini", proj, monkeypatch)
    assert (out / "conf.ini").read_text() == "x\n"
    rows = _outside(cfg)
    assert [(r["matched_rule"], r["action_raw"]) for r in rows] == [
        ("sys_outside_openat_trunc", f"[syscall] openat_trunc {out / 'conf.ini'}")]
    assert recovery.load_entries(cfg.recovery_dir) == []


def test_4_one_receipt_per_file_per_run(tmp_path, monkeypatch):
    proj, out = _dirs(tmp_path)
    f = out / "log.txt"
    f.write_text("OLD\n")
    cfg, _ = _run(f"echo a > {f}; echo b > {f}; rm -f {f}", proj, monkeypatch)
    assert not f.exists()
    assert [r["matched_rule"] for r in _outside(cfg)] == ["sys_outside_openat_trunc"]


def test_5_temp_dirs_devices_and_the_commands_own_files_are_not_recorded(tmp_path, monkeypatch):
    proj, out = _dirs(tmp_path)
    (out / "t.txt").write_text("TEMP\n")
    # tmp_path is under the temp dir: with the real skip list it is skipped.
    cfg, _ = _run(f"rm -f {out / 't.txt'}; echo x > /dev/null", proj, monkeypatch, temp_skipped=True)
    assert not (out / "t.txt").exists()
    assert _outside(cfg) == []
    # A file the command creates itself, outside, and then removes.
    cfg, _ = _run(f"echo x > {out / 'own.txt'}; rm -f {out / 'own.txt'}", proj, monkeypatch)
    assert _outside(cfg) == []


def test_6_an_ignored_directory_inside_the_project_is_not_outside(tmp_path, monkeypatch):
    proj, _ = _dirs(tmp_path)
    (proj / "node_modules").mkdir()
    (proj / "node_modules" / "x.js").write_text("1\n")
    cfg, _ = _run("rm -f node_modules/x.js", proj, monkeypatch)
    assert not (proj / "node_modules" / "x.js").exists()
    assert (_outside(cfg), recovery.load_entries(cfg.recovery_dir)) == ([], [])


def test_7_a_run_is_capped_with_one_closing_receipt(tmp_path, monkeypatch):
    proj, out = _dirs(tmp_path)
    for i in range(4):
        (out / f"f{i}.txt").write_text(f"{i}\n")
    monkeypatch.setattr(syscall_guard, "_OUTSIDE_CAP", 2, raising=False)
    cfg, _ = _run(" ; ".join(f"rm -f {out / f'f{i}.txt'}" for i in range(4)), proj, monkeypatch)
    assert [p.name for p in out.iterdir()] == []
    rows = _outside(cfg)
    assert [r["matched_rule"] for r in rows][2:] == ["sys_outside_cap"]
    assert len(rows) == 3
    assert [r["action_raw"].rsplit("/", 1)[-1] for r in rows[:2]] == ["f0.txt", "f1.txt"]
    assert "More than 2 files outside the project" in rows[2]["reason"]
