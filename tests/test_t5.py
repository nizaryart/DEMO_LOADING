from __future__ import annotations

import os
import pytest


def test_every_surface_has_a_non_empty_hint_and_no_hint_is_dead():
    from demo_cli.classify import (
        _NONRECOVERABLE_SURFACES,
        _EXTERNAL_IRREVERSIBLE,
        _LOCAL_UNRECOVERABLE,
    )
    from demo_cli import policy

    producible = (
        {label for label, _rx in _NONRECOVERABLE_SURFACES}
        | set(_EXTERNAL_IRREVERSIBLE.values())
        | set(_LOCAL_UNRECOVERABLE.values())
        | {
            "managed_database",
            policy.surface_of("db:h/x"),
            policy.surface_of("device:/dev/sda"),
            # M2.2a: git's own labels
            policy.surface_of("vcs-remote:origin"),
            policy.surface_of("vcs-local:reflog"),
            policy.surface_of("x:y"),
        }
    )
    assert producible == set(policy.RECOVERY_HINTS)
    for k, v in policy.RECOVERY_HINTS.items():
        assert bool(v and v.strip())


def test_escalation_names_hint_end_to_end_per_family(tmp_path):
    from demo_cli.guard import Guard
    from demo_cli.config import Config
    from demo_cli.decide import ESCALATE
    from demo_cli import policy

    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))

    # terraform destroy -> "the Terraform state backend's version history, then re-apply"
    r1 = g.evaluate("terraform destroy")
    assert r1.decision.decision == ESCALATE
    assert "the Terraform state backend's version history, then re-apply" in " ".join(r1.decision.next_steps)

    # kubectl delete pod x -> cluster_resource_delete hint
    r2 = g.evaluate("kubectl delete pod x")
    assert r2.decision.decision == ESCALATE
    assert "the manifests in version control, or a cluster backup (Velero / etcd snapshot)" in " ".join(r2.decision.next_steps)

    # mail -s hi a@b.c < f -> external_email hint
    r3 = g.evaluate("mail -s hi a@b.c < f")
    assert r3.decision.decision == ESCALATE
    assert "none - a sent message cannot be recalled" in " ".join(r3.decision.next_steps)

    # psql postgres://db.example.com/app -c "DELETE FROM t" -> surface remote_database and its hint
    r4 = g.evaluate('psql postgres://db.example.com/app -c "DELETE FROM t"')
    assert r4.decision.decision == ESCALATE
    assert r4.decision.surface == "remote_database"
    assert "the database's PITR / snapshot" in " ".join(r4.decision.next_steps)


def test_statement_matches_table():
    from demo_cli.engine.effects import CREATE, REF, SERVICE_KEEP
    from demo_cli import policy, protection

    allowed_remote = {k for k, v in policy.REMOTE_POLICY.items() if v == policy.ALLOW}
    # M2.2a (msg to come), ruling (c): REF joins them - a history move the
    # repository's own reflog brings back is allowed and listed.
    assert allowed_remote == {CREATE, SERVICE_KEEP, REF}
    assert "only adds" in protection.THREAT_MODEL
    assert "reflog" in protection.THREAT_MODEL
    assert "always stopped" not in protection.THREAT_MODEL


def test_one_judgement_engine_and_guard_agree(tmp_path):
    import sqlite3
    from demo_cli.guard import Guard
    from demo_cli.config import Config
    from demo_cli.engine.rules import RULES
    from demo_cli.engine.simulate import simulate
    from demo_cli.engine.verdict import verdict

    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    (tmp_path / "dir").mkdir()
    (tmp_path / "dir" / "f.txt").write_text("inside", encoding="utf-8")
    db_file = tmp_path / "app.db"
    con = sqlite3.connect(str(db_file))
    con.execute("CREATE TABLE t (id INT)")
    con.commit()
    con.close()

    cfg = Config(mode="enforce", project_root=str(tmp_path))
    g = Guard(config=cfg)

    # One expected decision per command, written out, not computed:
    # ALLOW -> ALLOW, REVERSIBLE -> REVERSIBLE, ESCALATE -> ESCALATE.
    commands = [
        ("rm a.txt", "REVERSIBLE"),
        ("rm -rf dir", "REVERSIBLE"),
        ("echo x > new.txt", "ALLOW"),
        ('sqlite3 app.db "DROP TABLE t"', "REVERSIBLE"),
        ('psql postgres://db.example.com/app -c "DROP TABLE t"', "ESCALATE"),
    ]

    for cmd, expected in commands:
        impact = simulate(cmd, RULES, cwd=str(tmp_path))
        v_dec, _ = verdict(impact, cfg)
        r = g.evaluate(cmd)
        assert v_dec == expected, f"verdict mismatch for {cmd}: {v_dec} != {expected}"
        assert r.decision.decision == expected, f"guard mismatch for {cmd}: {r.decision.decision} != {expected}"
        assert v_dec == r.decision.decision, f"unification mismatch for {cmd}"


@pytest.mark.skipif(
    os.name == "nt",
    reason="no /dev or /etc on Windows: _host_path maps them to unknown, by design (msg 035)",
)
def test_one_judgement_engine_and_guard_agree_posix_paths(tmp_path):
    from demo_cli.guard import Guard
    from demo_cli.config import Config
    from demo_cli.engine.rules import RULES
    from demo_cli.engine.simulate import simulate
    from demo_cli.engine.verdict import verdict

    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    cfg = Config(mode="enforce", project_root=str(tmp_path))
    g = Guard(config=cfg)

    commands = [
        ("cat a.txt > /dev/sda", "ESCALATE"),
        ("rm /etc/hostname", "ESCALATE"),
    ]

    for cmd, expected in commands:
        impact = simulate(cmd, RULES, cwd=str(tmp_path))
        v_dec, _ = verdict(impact, cfg)
        r = g.evaluate(cmd)
        assert v_dec == expected, f"verdict mismatch for {cmd}: {v_dec} != {expected}"
        assert r.decision.decision == expected, f"guard mismatch for {cmd}: {r.decision.decision} != {expected}"
        assert v_dec == r.decision.decision, f"unification mismatch for {cmd}"


def test_checkpoint_entry_survives_a_copy(tmp_path):
    from demo_cli import checkpoint, config, recovery

    (tmp_path / "hello.txt").write_text("content", encoding="utf-8")
    cfg = config.Config(project_root=str(tmp_path), checkpoint={"enabled": True})
    res = checkpoint.capture(cfg, "rm hello.txt")
    assert res.ok
    entries = recovery.load_entries(str(tmp_path / ".demo_cli" / "recovery"))
    assert len(entries) == 1
    e = entries[0]
    assert e.get("scope") == "checkpoint"
    assert dict(e)["scope"] == "checkpoint"
    assert {**e}["scope"] == "checkpoint"
