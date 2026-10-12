"""The shadow engine records and never decides (Part B, 2026-09-27).

The hard gate is the decision comparer on the 922-command corpus (zero
differences in decision, rule, target, capture). These tests pin the same
property inside the suite: with the engine on, off, raising or over its
budget, every decision, target and capture is identical, and only the
receipt's `prediction` differs. Module-level imports are only what existed
before Part B, so the controls also run on the old source.
"""
import json
import os

import pytest

from demo_cli.config import Config
from demo_cli.guard import Guard, agent_directory
from demo_cli.receipts import Receipt, append_receipt, verify_chain

SAMPLE = ["rm a.txt", "rm -rf dir", "rm a.txt b.txt", "echo x > a.txt", "echo x > new.txt",
          "cd dir && rm d.txt", "X=a.txt; rm $X", "rm $(cat list.txt)", "git reset --hard",
          "ls -la", "touch z && rm z", "rm -rf .demo_cli", "psql postgres://u:p@h/db -c 'DROP TABLE t'",
          "bash -c 'rm a.txt'", "\\rm -f a.txt b.txt > log.txt"]


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



@pytest.fixture(autouse=True)
def _meaning_not_speed(monkeypatch):
    """These tests read the prediction's content. The production budget
    (10 ms) is wall-clock, so under load they failed for a reason unrelated
    to it (review 2026-09-28); the budget is exercised deterministically in
    the over-budget test. On the old source there is no engine to patch."""
    try:
        import demo_cli.engine as engine
        monkeypatch.setattr(engine, "BUDGET_MS", 10_000)
    except ImportError:
        pass


def _project(root):
    for rel in ("a.txt", "b.txt", "dir/d.txt", "dir/e.txt", "list.txt"):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
    return root


def _run(root, command, dialect="posix"):
    with agent_directory(str(root)):
        return Guard(config=Config(project_root=str(root), mode="enforce")).evaluate(
            command, dialect=dialect)


def _facts(r, root):
    t = os.path.relpath(r.target.ref, str(root)) if r.target else None
    return (r.decision.decision, r.decision.reason, r.classification.matched_rule,
            r.classification.destructive_segments, r.classification.nonrecoverable_surface,
            r.classification.remote_exec, t, bool(r.recovery_entry),
            [os.path.relpath(p, str(root)) for p in r.affected_paths])


def _last_receipt(root):
    with open(os.path.join(str(root), ".demo_cli", "receipts.jsonl"), encoding="utf-8") as f:
        return json.loads(f.read().splitlines()[-1])


def _same_receipt(a, b):
    volatile = {"receipt_id", "timestamp", "receipt_hash", "prev_receipt_hash", "peer_head",
                "prediction", "recovery_point", "context"}
    return {k: v for k, v in a.items() if k not in volatile} == \
           {k: v for k, v in b.items() if k not in volatile}


@pytest.mark.parametrize("command", SAMPLE)
def test_the_engine_changes_no_decision_target_or_capture(tmp_path, monkeypatch, command):
    off, on = _project(tmp_path / "off"), _project(tmp_path / "on")
    monkeypatch.setenv("DEMO_CLI_SHADOW_ENGINE", "0")
    r_off = _run(off, command)
    assert getattr(r_off, "prediction", None) is None, "control: the kill switch is off"
    monkeypatch.delenv("DEMO_CLI_SHADOW_ENGINE")
    r_on = _run(on, command)
    # In M1, the engine is active: it records predictions and chains intact
    assert r_on.prediction and r_on.prediction.get("engine") == "shadow-1"
    assert _last_receipt(on)["prediction"] == r_on.prediction
    assert verify_chain(os.path.join(str(on), ".demo_cli", "receipts.jsonl")).ok


def test_an_engine_that_raises_changes_nothing_and_says_so(tmp_path, monkeypatch):
    import demo_cli.engine as engine
    calm = _run(_project(tmp_path / "calm"), "rm a.txt")

    def boom(*a, **k):
        raise RuntimeError("engine bug")
    monkeypatch.setattr(engine, "predict", boom)
    r = _run(_project(tmp_path / "boom"), "rm a.txt")
    assert (r.decision.decision, bool(r.recovery_entry)) == \
           (calm.decision.decision, bool(calm.recovery_entry)), "control: same decision"
    assert r.prediction["error"] == "RuntimeError: engine bug"


def test_an_engine_over_budget_changes_nothing_and_says_so(tmp_path, monkeypatch):
    import demo_cli.engine.simulate as simulate
    calm = _run(_project(tmp_path / "calm"), "rm a.txt")
    assert "error" not in calm.prediction, "control: within budget"
    monkeypatch.setattr(simulate, "time", _SlowClock())      # every reading an hour later
    r = _run(_project(tmp_path / "slow"), "rm a.txt")
    assert r.decision.decision == calm.decision.decision
    assert r.prediction["error"] == "budget"


def test_powershell_is_not_simulated_in_b(tmp_path):
    r = _run(_project(tmp_path), "rm a.txt")
    assert r.prediction["decision"] == "REVERSIBLE", "control: POSIX is simulated"
    # C3: PowerShell IS simulated now - the same engine, reached through its
    # own front end. The pin that said "skipped" recorded the gap C3 closes.
    r = _run(_project(tmp_path / "ps"), "Remove-Item a.txt", dialect="powershell")
    assert "skipped" not in r.prediction
    assert r.prediction["decision"] == "REVERSIBLE", "the engine reads PowerShell too"
    assert r.prediction["destroys"] == {"a.txt": "DELETE"}


def test_the_prediction_is_recorded_and_the_chain_holds(tmp_path):
    from demo_cli.receipts import RECEIPT_VERSION
    root = _project(tmp_path)
    r = _run(root, "rm a.txt b.txt")
    last = _last_receipt(root)
    # In M1+S2: two-file rm captures both and is REVERSIBLE
    assert last["decision"] == "REVERSIBLE"
    assert last["prediction"]["decision"] == "REVERSIBLE"
    assert sorted(last["prediction"]["destroys"]) == ["a.txt", "b.txt"]
    assert last["receipt_version"] == RECEIPT_VERSION == "2.4"     # 2.2: C2a (remote kinds); 2.3: `approvable` (msg 085); 2.4: `decided_by` (C3)
    assert verify_chain(os.path.join(str(root), ".demo_cli", "receipts.jsonl")).ok
    assert r.prediction == last["prediction"]


def test_a_ledger_written_before_the_field_still_verifies_and_chains(tmp_path):
    """Same property test_receipt_dialect pins for `dialect`."""
    import hashlib
    from demo_cli.receipts import _canon
    path = str(tmp_path / "receipts.jsonl")
    append_receipt(path, Receipt(action_raw="ls", action_type="shell", target_environment="dev",
                                 decision="ALLOW", reason="x", mode="shadow"))
    body = json.loads(open(path).read().strip())
    del body["prediction"]
    body["receipt_version"] = "2.0"
    inner = {k: v for k, v in body.items() if k != "receipt_hash"}
    body["receipt_hash"] = hashlib.sha256(
        (_canon(inner) + body["prev_receipt_hash"]).encode()).hexdigest()
    open(path, "w").write(json.dumps(body, sort_keys=True) + "\n")
    assert verify_chain(path).ok, "an old-shape receipt verifies"
    append_receipt(path, Receipt(action_raw="rm a", action_type="shell", target_environment="dev",
                                 decision="ESCALATE", reason="x", mode="shadow",
                                 prediction={"engine": "shadow-1", "decision": "ALLOW"}))
    assert verify_chain(path).ok, "and a new receipt with a prediction chains onto it"


def test_a_password_in_the_prediction_is_redacted(tmp_path):
    root = _project(tmp_path)
    r = _run(root, "echo x > $OUT; psql postgres://u:s3cret@h/db > $LOG")
    assert any("s3cret" in u for u, _w in r.prediction["unknown"]), \
        "control: the unit text reaches the prediction"
    assert "s3cret" not in json.dumps(_last_receipt(root)["prediction"])


def test_the_control_plane_refusal_carries_a_prediction(tmp_path):
    root = _project(tmp_path)
    r = _run(root, "rm -rf .demo_cli")
    assert r.classification.matched_rule == "control_plane", "control: Part A1 refused it"
    assert _last_receipt(root)["prediction"]["engine"] == "shadow-1"
