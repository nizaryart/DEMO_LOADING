from __future__ import annotations

import os
import sys
import pytest

from conftest import assert_restores
from demo_cli import syscall_guard


@pytest.mark.skipif(os.name == "nt", reason="B0.1 (msg 037): Windows process_time ticks every 15.625 ms (measured), so the budget uses wall time there and CPU time cannot differ from it")
def test_budget_counts_cpu_not_wall(monkeypatch):
    from demo_cli.engine import simulate
    from demo_cli.engine.simulate import Budget

    class FakeTime:
        def __init__(self):
            self.cpu = 0.0
            self.wall = 0.0

        def process_time(self):
            return self.cpu

        def thread_time(self):
            return self.cpu

        def perf_counter(self):
            return self.wall

    fake = FakeTime()
    monkeypatch.setattr(simulate, "time", fake)

    # 1. CPU +0 ms per reading and wall +50 ms per reading -> Budget(10).check() passes
    fake.cpu = 0.0
    fake.wall = 0.0
    b1 = Budget(10)
    fake.wall = 0.050
    b1.check()


def test_budget_deterministic(monkeypatch):
    from demo_cli.engine import simulate
    from demo_cli.engine.simulate import Budget, BudgetExceeded

    class FakeTime:
        def __init__(self):
            self.cpu = 0.0
            self.wall = 0.0

        def process_time(self):
            return self.cpu

        def thread_time(self):
            return self.cpu

        def perf_counter(self):
            return self.wall

    fake = FakeTime()
    monkeypatch.setattr(simulate, "time", fake)

    # 2. Wall +300 ms -> it raises (the ceiling)
    fake.cpu = 0.0
    fake.wall = 0.0
    b2 = Budget(10)
    fake.wall = 0.300
    with pytest.raises(BudgetExceeded):
        b2.check()

    # 3. CPU +11 ms -> it raises
    fake.cpu = 0.0
    fake.wall = 0.0
    b3 = Budget(10)
    fake.cpu = 0.011
    fake.wall = 0.011
    with pytest.raises(BudgetExceeded):
        b3.check()


def test_budget_paused(monkeypatch):
    from demo_cli.engine import simulate
    from demo_cli.engine.simulate import Budget, BudgetExceeded

    class FakeTime:
        def __init__(self):
            self.cpu = 0.0
            self.wall = 0.0

        def process_time(self):
            return self.cpu

        def thread_time(self):
            return self.cpu

        def perf_counter(self):
            return self.wall

    fake = FakeTime()
    monkeypatch.setattr(simulate, "time", fake)

    b = Budget(10)
    with b.paused():
        fake.cpu = 0.020
        fake.wall = 0.300
    b.check()

    fake.cpu = 0.0
    fake.wall = 0.0
    b_control = Budget(10)
    fake.cpu = 0.020
    fake.wall = 0.300
    with pytest.raises(BudgetExceeded):
        b_control.check()


def test_retry_on_budget_exceeded(tmp_path, monkeypatch):
    from demo_cli import engine
    from demo_cli.config import Config
    from demo_cli.guard import Guard, agent_directory
    from demo_cli.decide import REVERSIBLE
    from demo_cli.engine.simulate import BudgetExceeded
    from demo_cli.engine import RETRY_BUDGET_MS

    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    real_predict = engine.predict
    calls = []

    def mock_predict(command, cfg, *args, **kwargs):
        calls.append((command, kwargs.get("budget_ms")))
        if len(calls) == 1:
            raise BudgetExceeded()
        return real_predict(command, cfg, *args, **kwargs)

    monkeypatch.setattr(engine, "predict", mock_predict)

    cfg = Config(mode="enforce", project_root=str(tmp_path))
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate("rm a.txt")

    assert r.decision.decision == REVERSIBLE
    assert r.recovery_entry is not None
    assert_restores(r.recovery_entry, str(tmp_path), {"a.txt": b"hello"})
    assert r.prediction is not None
    assert r.prediction.get("retried") is True
    assert "error" not in r.prediction
    assert len(calls) == 2
    assert calls[1][1] == RETRY_BUDGET_MS


def test_no_retry_on_runtime_error(tmp_path, monkeypatch):
    from demo_cli import engine
    from demo_cli.config import Config
    from demo_cli.guard import Guard, agent_directory

    calls = []

    def mock_predict(command, cfg, *args, **kwargs):
        calls.append(command)
        raise RuntimeError("bug in engine")

    monkeypatch.setattr(engine, "predict", mock_predict)

    cfg = Config(mode="enforce", project_root=str(tmp_path))
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate("rm a.txt")

    assert len(calls) == 1
    assert r.prediction is not None
    assert r.prediction.get("error", "").startswith("RuntimeError")
    assert r.prediction.get("retried") is not True


def test_never_looser_no_net(tmp_path, monkeypatch):
    from demo_cli import engine
    from demo_cli.config import Config
    from demo_cli.guard import Guard, agent_directory
    from demo_cli.decide import ESCALATE
    from demo_cli.engine.simulate import BudgetExceeded

    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")

    def mock_predict(command, cfg, *args, **kwargs):
        raise BudgetExceeded()

    monkeypatch.setattr(engine, "predict", mock_predict)

    cfg = Config(mode="enforce", project_root=str(tmp_path), checkpoint={"enabled": False})
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate("r''m a.txt", can_supervise=False)

    assert r.decision.decision == ESCALATE
    assert r.classification.matched_rule == "engine_unavailable"
    assert r.decision.reason.startswith("demo_cli could not finish reading this command (engine: budget)")
    assert (tmp_path / "a.txt").read_text(encoding="utf-8") == "hello"


@pytest.mark.skipif(not syscall_guard.available(), reason="needs the Linux syscall guard (ptrace)")
def test_never_looser_with_net(tmp_path, monkeypatch):
    from demo_cli import engine
    from demo_cli.config import Config
    from demo_cli.guard import Guard, agent_directory
    from demo_cli.engine.simulate import BudgetExceeded

    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")

    def mock_predict(command, cfg, *args, **kwargs):
        raise BudgetExceeded()

    monkeypatch.setattr(engine, "predict", mock_predict)

    cfg = Config(mode="enforce", project_root=str(tmp_path), checkpoint={"enabled": False})
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate("r''m a.txt", can_supervise=True)

    assert r.decision.decision == "SUPERVISED"
    assert r.rewrite is not None
    assert r.rewrite.startswith(f"{sys.executable} -m demo_cli run --group ")


def test_control_engine_working_r_quote_m(tmp_path):
    from demo_cli.config import Config
    from demo_cli.guard import Guard, agent_directory
    from demo_cli.decide import REVERSIBLE

    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    cfg = Config(mode="enforce", project_root=str(tmp_path))
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate("r''m a.txt")

    assert r.decision.decision == REVERSIBLE
    assert r.recovery_entry is not None
    assert_restores(r.recovery_entry, str(tmp_path), {"a.txt": b"hello"})


def test_kill_switch_unchanged(tmp_path, monkeypatch):
    from demo_cli.config import Config
    from demo_cli.guard import Guard, agent_directory
    from demo_cli.decide import ALLOW

    monkeypatch.setenv("DEMO_CLI_SHADOW_ENGINE", "0")
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    cfg = Config(mode="enforce", project_root=str(tmp_path))
    g = Guard(config=cfg)
    # the user switched the engine off: legacy decides, by choice (msg 037)
    with agent_directory(str(tmp_path)):
        r = g.evaluate("r''m a.txt")

    assert r.decision.decision == ALLOW
    assert r.prediction is None


def test_legacy_capture_still_wins(tmp_path, monkeypatch):
    from demo_cli import engine
    from demo_cli.config import Config
    from demo_cli.guard import Guard, agent_directory
    from demo_cli.decide import REVERSIBLE
    from demo_cli.engine.simulate import BudgetExceeded

    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")

    def mock_predict(command, cfg, *args, **kwargs):
        raise BudgetExceeded()

    monkeypatch.setattr(engine, "predict", mock_predict)

    cfg = Config(mode="enforce", project_root=str(tmp_path))
    g = Guard(config=cfg)
    with agent_directory(str(tmp_path)):
        r = g.evaluate("rm a.txt")

    assert r.decision.decision == REVERSIBLE
    assert r.recovery_entry is not None
    assert_restores(r.recovery_entry, str(tmp_path), {"a.txt": b"hello"})
