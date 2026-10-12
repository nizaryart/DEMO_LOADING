import os
import shutil
import sqlite3
import subprocess
import pytest

from demo_cli import recovery
from demo_cli.config import Config, TargetRule
from demo_cli.context import Intent
from demo_cli.decide import ALLOW, CONTEXT_MISMATCH, ESCALATE, REVERSIBLE
from demo_cli.guard import Guard, agent_directory


# ---------------------------------------------------------------------
# Item A: demo_cli's own files: use the engine's knowledge too
# ---------------------------------------------------------------------

def test_m2_a_control_plane_escalates(tmp_path):
    (tmp_path / ".demo_cli.toml").write_text("mode = 'enforce'\n")
    (tmp_path / "a.txt").write_text("hello\n")
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)

    rows = [
        "tee .demo_cli.toml </dev/null",
        "ln -sf a.txt .demo_cli.toml",
        "install a.txt .demo_cli.toml",
        "rsync a.txt .demo_cli.toml",
        "printf x | tee -a .demo_cli.toml",
    ]
    with agent_directory(str(tmp_path)):
        for cmd in rows:
            r = g.evaluate(cmd)
            assert r.decision.decision == ESCALATE
            assert r.classification.matched_rule == "control_plane"


def test_m2_a_control_plane_controls_with_notes(tmp_path):
    (tmp_path / "notes.txt").write_text("original\n")
    (tmp_path / "a.txt").write_text("hello\n")
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)

    with agent_directory(str(tmp_path)):
        # 1. tee notes.txt </dev/null: truncates existing notes.txt -> REVERSIBLE
        r1 = g.evaluate("tee notes.txt </dev/null")
        assert r1.decision.decision == REVERSIBLE
        assert r1.classification.matched_rule != "control_plane"

        # 2. ln -sf a.txt notes.txt: overwrites existing notes.txt -> REVERSIBLE
        r2 = g.evaluate("ln -sf a.txt notes.txt")
        assert r2.decision.decision == REVERSIBLE
        assert r2.classification.matched_rule != "control_plane"

        # 3. install a.txt notes.txt: overwrites existing notes.txt -> REVERSIBLE
        r3 = g.evaluate("install a.txt notes.txt")
        assert r3.decision.decision == REVERSIBLE
        assert r3.classification.matched_rule != "control_plane"

        # 4. rsync a.txt notes.txt: overwrites existing notes.txt -> REVERSIBLE
        r4 = g.evaluate("rsync a.txt notes.txt")
        assert r4.decision.decision == REVERSIBLE
        assert r4.classification.matched_rule != "control_plane"

        # 5. printf x | tee -a notes.txt: appends to notes.txt, non-destructive -> ALLOW
        r5 = g.evaluate("printf x | tee -a notes.txt")
        assert r5.decision.decision == ALLOW
        assert r5.classification.matched_rule != "control_plane"


def test_m2_a_known_limit_python_open_control_plane(tmp_path):
    (tmp_path / ".demo_cli.toml").write_text("mode = 'enforce'\n")
    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate('python3 -c "open(\'.demo_cli.toml\',\'w\')\"')
        # Python script is not modelled at text layer -> ALLOW (supervised net handles at runtime)
        assert r.decision.decision == ALLOW


# ---------------------------------------------------------------------
# Item B: The syscall guard must REFUSE writes to demo_cli's own files
# ---------------------------------------------------------------------

def test_m2_b_syscall_guard_refuses_control_plane(tmp_path, monkeypatch):
    from demo_cli.syscall_guard import available as syscall_available, run_supervised
    from demo_cli.receipts import load_receipts
    if not syscall_available():
        pytest.skip("syscall_guard not available on this platform")

    monkeypatch.chdir(tmp_path)
    cfg_file = tmp_path / ".demo_cli.toml"
    initial_bytes = b"mode = 'enforce'\nsecret = 123\n"
    cfg_file.write_bytes(initial_bytes)
    cfg = Config(project_root=str(tmp_path), mode="enforce")

    # 1. Truncate / overwrite via python -> bytes UNCHANGED, non-zero exit, ESCALATE receipt
    ret1 = run_supervised(
        ["python3", "-c", "open('.demo_cli.toml','w').write('pwned')"],
        cfg,
    )
    assert cfg_file.read_bytes() == initial_bytes
    assert ret1 != 0
    receipts1 = load_receipts(cfg.receipts_path)
    assert any(rc.get("decision") == ESCALATE and rc.get("matched_rule") == "control_plane" for rc in receipts1)

    # 2. Rename / mv .demo_cli.toml -> file still exists with same bytes
    ret2 = run_supervised(
        ["mv", ".demo_cli.toml", "x.toml"],
        cfg,
    )
    assert cfg_file.exists()
    assert cfg_file.read_bytes() == initial_bytes
    assert not (tmp_path / "x.toml").exists()

    # 3. Append via python -> unchanged
    ret3 = run_supervised(
        ["python3", "-c", "open('.demo_cli.toml','a').write('x')"],
        cfg,
    )
    assert cfg_file.read_bytes() == initial_bytes

    # Control: notes.txt allowed, snapshotted, and restores
    notes = tmp_path / "notes.txt"
    notes_bytes = b"original notes\n"
    notes.write_bytes(notes_bytes)
    ret4 = run_supervised(
        ["python3", "-c", "open('notes.txt','w').write('x')"],
        cfg,
    )
    assert ret4 == 0
    receipts4 = load_receipts(cfg.receipts_path)
    entries = recovery.load_entries(cfg.recovery_dir)
    assert entries
    assert_restores(entries[-1], tmp_path, {"notes.txt": notes_bytes})


# ---------------------------------------------------------------------
# Item C: Clean the engine branch of guard.py: one source of truth
# ---------------------------------------------------------------------

def test_m2_c1_sqlite_drop_table_reversible(tmp_path):
    db_path = tmp_path / "app.db"
    con = sqlite3.connect(str(db_path))
    con.execute("CREATE TABLE t (id INT, val TEXT)")
    con.execute("INSERT INTO t VALUES (1, 'val')")
    con.commit()
    con.close()
    initial_bytes = db_path.read_bytes()

    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate('sqlite3 app.db "DROP TABLE t"')

    assert r.decision.decision == REVERSIBLE
    assert_restores(r.recovery_entry, tmp_path, {"app.db": initial_bytes})

    # Control: psql without URL escalates
    with agent_directory(str(tmp_path)):
        r_ctrl = g.evaluate('psql -c "DROP TABLE t"; rm a.txt')
        assert r_ctrl.decision.decision == ESCALATE


def test_m2_c2_postgres_engine_target(tmp_path, monkeypatch):
    recorded_targets = []
    def fake_snapshot_set(targets, *args, **kwargs):
        recorded_targets.extend(targets)
        return {"recovery_point": "fake-rp", "targets": [t.ref for t in targets]}

    monkeypatch.setattr(recovery, "snapshot_set", fake_snapshot_set)

    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)

    with agent_directory(str(tmp_path)):
        # Two-URL line -> target ends with /db, never /other; REVERSIBLE
        cmd1 = "echo postgres://localhost/other; psql postgres://localhost/db -c 'DELETE FROM t'"
        r1 = g.evaluate(cmd1)
        assert r1.decision.decision == REVERSIBLE
        assert any(t.ref == "postgres://localhost/db" for t in recorded_targets)
        assert not any("other" in t.ref for t in recorded_targets)

        # Single local URL
        recorded_targets.clear()
        cmd2 = "psql postgres://localhost/db -c 'DELETE FROM t'"
        r2 = g.evaluate(cmd2)
        assert r2.decision.decision == REVERSIBLE
        assert any(t.ref == "postgres://localhost/db" for t in recorded_targets)

        # Remote URL -> ESCALATE, nothing recorded
        recorded_targets.clear()
        cmd3 = "psql postgres://db.example.com/app -c 'DELETE FROM t'"
        r3 = g.evaluate(cmd3)
        assert r3.decision.decision == ESCALATE
        assert len(recorded_targets) == 0


def test_m2_c3_outside_destroys_and_creations(tmp_path):
    outside_dir = tmp_path.parent / f"outside_dir_{tmp_path.name}"
    outside_dir.mkdir(exist_ok=True)
    outside_file = outside_dir / "outside.txt"
    outside_file.write_text("existing content\n")

    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)

    with agent_directory(str(tmp_path)):
        # 1. rm ../outside.txt (exists) -> ESCALATE
        rel_outside = os.path.relpath(str(outside_file), str(tmp_path)).replace(os.sep, "/")
        r1 = g.evaluate(f"rm {rel_outside}")
        assert r1.decision.decision == ESCALATE

        # 2. rm -rf <absent outside> -> ALLOW (nothing exists, nothing lost)
        absent_outside = outside_dir / "absent_file.txt"
        rel_absent = os.path.relpath(str(absent_outside), str(tmp_path)).replace(os.sep, "/")
        r2 = g.evaluate(f"rm -rf {rel_absent}")
        assert r2.decision.decision == ALLOW

        # 3. echo x > ../outside_new.txt (absent) -> ALLOW
        outside_new = outside_dir / "outside_new.txt"
        if outside_new.exists():
            outside_new.unlink()
        rel_outside_new = os.path.relpath(str(outside_new), str(tmp_path)).replace(os.sep, "/")
        r3 = g.evaluate(f"echo x > {rel_outside_new}")
        assert r3.decision.decision == ALLOW

        # 4. echo x > ../outside.txt (exists) -> ESCALATE (truncation outside project)
        r4 = g.evaluate(f"echo x > {rel_outside}")
        assert r4.decision.decision == ESCALATE


def test_m2_c4_classify_flags_ignored_on_engine_path(tmp_path, monkeypatch):
    a = tmp_path / "a.txt"
    a_bytes = b"hello a\n"
    a.write_bytes(a_bytes)

    import demo_cli.guard as guard_mod

    orig_classify = guard_mod.classify_pipeline
    def fake_classify(cmd, dialect="posix"):
        c = orig_classify(cmd, dialect)
        c.nonrecoverable_surface = "cloud_resource_delete"
        c.remote_exec = True
        return c

    monkeypatch.setattr(guard_mod, "classify_pipeline", fake_classify)

    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)

    with agent_directory(str(tmp_path)):
        # On engine path (POSIX): classify flags ignored -> REVERSIBLE with assert_restores
        r_posix = g.evaluate("rm a.txt")
        assert r_posix.decision.decision == REVERSIBLE
        assert_restores(r_posix.recovery_entry, tmp_path, {"a.txt": a_bytes})

        # C3: PowerShell is on the engine path too, so the faked classify
        # flags are ignored in BOTH dialects - the same line, the same
        # answer, whichever shell wrote it. (Before C3 this was the control
        # showing the old text path still read those flags and escalated.)
        r_ps = g.evaluate("Remove-Item a.txt", dialect="powershell")
        assert r_ps.decision.decision == REVERSIBLE
        assert_restores(r_ps.recovery_entry, tmp_path, {"a.txt": a_bytes})


# ---------------------------------------------------------------------
# Item D: Postgres secrets never stored, never on a command line
# ---------------------------------------------------------------------

def test_m2_d_pg_split_and_snapshot_secrets(tmp_path, monkeypatch):
    from demo_cli.recovery import _pg_split

    # 1. URL form
    url1 = "postgres://user:secret123@localhost:5432/mydb"
    no_pw1, pw1 = _pg_split(url1)
    assert "secret123" not in no_pw1
    assert no_pw1 == "postgres://user@localhost:5432/mydb"
    assert pw1 == "secret123"

    # URL without password
    url2 = "postgres://localhost/mydb"
    no_pw2, pw2 = _pg_split(url2)
    assert no_pw2 == "postgres://localhost/mydb"
    assert pw2 is None

    # Conninfo form
    ci1 = "host=localhost dbname=mydb password=secret123 user=app"
    no_pw_ci, pw_ci = _pg_split(ci1)
    assert "secret123" not in no_pw_ci
    assert pw_ci == "secret123"

    # Conninfo without password
    ci2 = "host=localhost dbname=mydb user=app"
    no_pw_ci2, pw_ci2 = _pg_split(ci2)
    assert no_pw_ci2 == ci2
    assert pw_ci2 is None

    # Snapshot test
    captured_argv = []
    captured_env = {}

    def fake_run(args, **kwargs):
        captured_argv.extend(args)
        captured_env.update(kwargs.get("env", {}))
        dump_path = args[args.index("-f") + 1]
        with open(dump_path, "wb") as f:
            f.write(b"PGDUMP")
        class FakeRes:
            returncode = 0
            stderr = ""
        return FakeRes()

    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/" + cmd)
    monkeypatch.setattr(subprocess, "run", fake_run)

    target = recovery.Target("postgres", url1, "db:localhost/mydb")
    entry = recovery.snapshot(target, str(tmp_path / ".recovery"), "snapshot", action="test")
    assert entry is not None

    # Assertions from item D:
    # - argv contains no password
    assert not any("secret123" in arg for arg in captured_argv)
    # - env["PGPASSWORD"] equals it
    assert captured_env.get("PGPASSWORD") == "secret123"
    # - recovery index file's TEXT contains no password
    entries_file = tmp_path / ".recovery" / "index.jsonl"
    assert "secret123" not in entries_file.read_text()
    assert entry["target"] == no_pw1

    # Conninfo snapshot test
    captured_argv.clear()
    captured_env.clear()
    target_ci = recovery.Target("postgres", ci1, "db:localhost/mydb")
    entry_ci = recovery.snapshot(target_ci, str(tmp_path / ".recovery"), "snapshot", action="test_ci")
    assert entry_ci is not None
    assert not any("secret123" in arg for arg in captured_argv)
    assert captured_env.get("PGPASSWORD") == "secret123"
    assert "secret123" not in entries_file.read_text()


# ---------------------------------------------------------------------
# Item E: The Edit/Write door decides through decide.py
# ---------------------------------------------------------------------

def test_m2_e_evaluate_file_edit_decides_through_decide(tmp_path):
    f = tmp_path / "existing.txt"
    initial_bytes = b"existing content\n"
    f.write_bytes(initial_bytes)

    cfg = Config(project_root=str(tmp_path), mode="enforce")
    g = Guard(config=cfg)

    # 1. Existing file -> REVERSIBLE + assert_restores
    r1 = g.evaluate_file_edit(str(f))
    assert r1.decision.decision == REVERSIBLE
    assert_restores(r1.recovery_entry, tmp_path, {"existing.txt": initial_bytes})

    # 2. New file -> ALLOW
    new_f = tmp_path / "new.txt"
    r2 = g.evaluate_file_edit(str(new_f))
    assert r2.decision.decision == ALLOW

    # 3. Project root -> ESCALATE with root reason text
    r3 = g.evaluate_file_edit(str(tmp_path))
    assert r3.decision.decision == ESCALATE
    assert "is the project root itself; capturing the whole tree" in r3.decision.reason

    # 4. File outside project -> ESCALATE with outside reason text
    outside_f = tmp_path.parent / f"outside_edit_{tmp_path.name}.txt"
    outside_f.write_text("outside\n")
    r4 = g.evaluate_file_edit(str(outside_f))
    assert r4.decision.decision == ESCALATE
    assert "outside the project root" in r4.decision.reason

    # 5. Link pointing out -> ESCALATE with link-out text
    link_out = tmp_path / "link_to_outside.txt"
    if hasattr(os, "symlink"):
        try:
            link_out.symlink_to(outside_f)
            r5 = g.evaluate_file_edit(str(link_out))
            assert r5.decision.decision == ESCALATE
            assert "links to" in r5.decision.reason
            assert "outside the project root" in r5.decision.reason
        except OSError:
            pass

    # 6. Existing file with declared intent mismatch -> CONTEXT_MISMATCH
    cfg.targets.append(TargetRule(match=str(f), env="staging"))
    mismatch_intent = Intent(env="production")
    r6 = g.evaluate_file_edit(str(f), intent=mismatch_intent)
    assert r6.decision.decision == CONTEXT_MISMATCH
    assert r6.mismatches == [("environment", "production", "staging")]


# ---------------------------------------------------------------------
# Item M2.1-C: Git Bash absolute paths
# ---------------------------------------------------------------------

def test_m2_1_c_host_path_mappings():
    from demo_cli.engine.simulate import _host_path

    # Windows mappings (Git Bash /c/... -> C:\...)
    assert _host_path("/c/Users/pc/x", windows=True) == r"C:\Users\pc\x"
    assert _host_path("/c", windows=True) == "C:\\"
    assert _host_path("/D/data/f.txt", windows=True) == r"D:\data\f.txt"
    assert _host_path("/tmp/x", windows=True) is None
    assert _host_path("rel/x", windows=True) == "rel/x"

    # With windows=False, everything is unchanged
    for p in ["/c/Users/pc/x", "/c", "/D/data/f.txt", "/tmp/x", "rel/x"]:
        assert _host_path(p, windows=False) == p


# ---------------------------------------------------------------------
# Item 022-1: recovery.restore on snapshot_set without patching
# ---------------------------------------------------------------------

def test_restore_snapshot_set_without_patching(tmp_path):
    f1 = tmp_path / "f1.txt"
    f2 = tmp_path / "f2.txt"
    f3 = tmp_path / "f3.txt"
    b1, b2, b3 = b"content 1\n", b"content 2\n", b"content 3\n"
    f1.write_bytes(b1)
    f2.write_bytes(b2)
    f3.write_bytes(b3)

    targets = [
        recovery.Target("file", str(f1), str(f1)),
        recovery.Target("file", str(f2), str(f2)),
        recovery.Target("file", str(f3), str(f3)),
    ]
    rec_dir = str(tmp_path / ".recovery")
    entry = recovery.snapshot_set(targets, rec_dir, strategy="snapshot", action="test")
    assert entry is not None
    assert entry["kind"] == "set"

    # Delete all 3 files
    f1.unlink()
    f2.unlink()
    f3.unlink()
    assert not f1.exists() and not f2.exists() and not f3.exists()

    # Restore with recovery.restore (NO patching)
    res = recovery.restore(entry)
    assert res.ok
    assert f1.read_bytes() == b1
    assert f2.read_bytes() == b2
    assert f3.read_bytes() == b3

    # Delete again and restore with recovery.restore_entry (NO patching)
    f1.unlink()
    f2.unlink()
    f3.unlink()
    ok = recovery.restore_entry(entry)
    assert ok is True
    assert f1.read_bytes() == b1
    assert f2.read_bytes() == b2
    assert f3.read_bytes() == b3


