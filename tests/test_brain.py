from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import replace

import pytest

from shahrah.brain import Brain, BrainConfig, describe, run_forever
from shahrah.models import ConfigError, Endpoint, Profile, User
from shahrah.oracle import Mode, OracleConfig
from shahrah.panel import PanelError, SyncPlan
from shahrah.prober import ProbeError, ProbeResult

FAST = OracleConfig(fail_streak=2, recover_streak=2, min_dwell_s=0, outage_after_cycles=2)


@pytest.fixture
def config(endpoint: Endpoint, users: list[User]) -> BrainConfig:
    b = replace(endpoint, name="exit-b", priority=1)
    a = replace(endpoint, name="exit-a", priority=0)
    return BrainConfig(
        endpoints=(a, b),
        probe_user=users[0],
        remarks={"exit-a": "Exit A", "exit-b": "Exit B"},
        oracle=FAST,
    )


class Script:
    """Scripted probe rounds: each call returns the next dict {name: ok}."""

    def __init__(self, *rounds: dict[str, bool]) -> None:
        self._rounds = list(rounds)

    def __call__(self) -> list[ProbeResult]:
        current = self._rounds.pop(0) if len(self._rounds) > 1 else self._rounds[0]
        return [
            ProbeResult(n, ok, 50.0 if ok else None, "" if ok else "refused")
            for n, ok in current.items()
        ]


class RecordingPanel:
    def __init__(self, fail: bool = False) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.fail = fail

    def __call__(self, ranking: Sequence[str]) -> SyncPlan:
        self.calls.append(tuple(ranking))
        if self.fail:
            raise PanelError("panel down")
        return SyncPlan(disable=(1,)) if len(ranking) < 2 else SyncPlan()


ALL_OK = {"exit-a": True, "exit-b": True}
A_DOWN = {"exit-a": False, "exit-b": True}


def test_healthy_cycle_syncs_ranking_once_then_stays_quiet(config: BrainConfig) -> None:
    panel = RecordingPanel()
    brain = Brain(config, Script(ALL_OK), panel, clock=lambda: 0.0)
    for _ in range(3):
        decision = brain.cycle()
    assert decision is not None and decision.state.mode is Mode.NORMAL
    assert panel.calls == [("exit-a", "exit-b")]  # unchanged ranking is not re-sent


def test_failure_is_confirmed_before_the_panel_is_changed(config: BrainConfig) -> None:
    panel = RecordingPanel()
    brain = Brain(config, Script(ALL_OK, ALL_OK, A_DOWN, A_DOWN), panel, clock=lambda: 0.0)
    brain.cycle()
    brain.cycle()
    panel.calls.clear()
    brain.cycle()  # first failure: hysteresis keeps exit-a healthy
    assert panel.calls == []
    brain.cycle()  # second consecutive failure: now it is unhealthy
    assert panel.calls == [("exit-b",)]


def test_total_outage_leaves_the_panel_untouched_and_retries_later(
    config: BrainConfig, caplog: pytest.LogCaptureFixture
) -> None:
    class SkippingPanel(RecordingPanel):
        def __call__(self, ranking: Sequence[str]) -> SyncPlan:
            self.calls.append(tuple(ranking))
            return SyncPlan(skipped_reason="no healthy path: leaving the panel untouched")

    panel = SkippingPanel()
    all_down = {"exit-a": False, "exit-b": False}
    brain = Brain(config, Script(ALL_OK, ALL_OK, all_down), panel, clock=lambda: 0.0)
    brain.cycle()
    brain.cycle()
    with caplog.at_level(logging.WARNING, logger="shahrah.brain"):
        for _ in range(3):
            brain.cycle()
    assert "panel untouched" in caplog.text
    assert brain.state.mode in {Mode.DEGRADED, Mode.OUTAGE}


def test_panel_failure_does_not_crash_and_is_retried(config: BrainConfig) -> None:
    panel = RecordingPanel(fail=True)
    brain = Brain(config, Script(ALL_OK), panel, clock=lambda: 0.0)
    assert brain.cycle() is not None
    panel.fail = False
    assert brain.cycle() is not None
    assert len(panel.calls) == 2  # the failed attempt was not recorded as synced


def test_prober_failure_skips_the_cycle_without_changing_state(config: BrainConfig) -> None:
    def broken() -> list[ProbeResult]:
        raise ProbeError("xray died")

    panel = RecordingPanel()
    brain = Brain(config, broken, panel, clock=lambda: 0.0)
    assert brain.cycle() is None
    assert panel.calls == []


def test_only_mapped_paths_are_sent_to_the_panel(config: BrainConfig) -> None:
    partial = replace(config, remarks={"exit-a": "Exit A"})
    panel = RecordingPanel()
    Brain(partial, Script(ALL_OK), panel, clock=lambda: 0.0).cycle()
    assert panel.calls == [("exit-a",)]


def test_brain_works_without_a_panel(config: BrainConfig) -> None:
    assert Brain(config, Script(ALL_OK), None, clock=lambda: 0.0).cycle() is not None


def test_describe_is_secret_free(config: BrainConfig) -> None:
    decision = Brain(config, Script(ALL_OK), None, clock=lambda: 0.0).cycle()
    assert decision is not None
    summary = describe(decision)
    assert set(summary) == {"mode", "active", "ranking", "reason"}
    assert "public_key" not in json.dumps(summary)


def test_run_forever_sleeps_between_cycles_and_stops(config: BrainConfig) -> None:
    brain = Brain(config, Script(ALL_OK), None, clock=lambda: 0.0)
    cycles: list[int] = []
    sleeps: list[float] = []

    def stop() -> bool:
        return len(sleeps) >= 3

    original = brain.cycle
    brain.cycle = lambda: cycles.append(1) or original()  # type: ignore[method-assign]
    run_forever(brain, 30.0, sleep=sleeps.append, stop=stop)
    assert len(cycles) == 3
    assert all(0 < s <= 30.0 for s in sleeps)


# -------------------------------------------------------------------------------- config


def _config_json(endpoint: Endpoint, probe_user: User) -> dict[str, object]:
    item = {
        "name": endpoint.name,
        "host": endpoint.host,
        "port": endpoint.port,
        "profile": "reality-vision",
        "public_key": endpoint.public_key,
        "short_id": endpoint.short_id,
        "sni": endpoint.sni,
    }
    return {
        "endpoints": [item],
        "probe_user": {"uuid": probe_user.uuid, "label": probe_user.label},
        "remarks": {endpoint.name: "Exit A"},
        "interval_s": 20,
        "oracle": {"fail_streak": 4},
    }


def test_config_loads_from_json(endpoint: Endpoint, users: list[User]) -> None:
    loaded = BrainConfig.from_json(json.dumps(_config_json(endpoint, users[0])))
    assert loaded.endpoints[0].profile is Profile.REALITY_VISION
    assert loaded.oracle.fail_streak == 4
    assert loaded.interval_s == 20


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d.update(endpoints=[]), "at least one endpoint"),
        (lambda d: d.update(remarks={"ghost": "X"}), "unknown endpoints"),
        (lambda d: d.update(interval_s=1), "hammer"),
        (lambda d: d.pop("probe_user"), "invalid"),
    ],
)
def test_bad_configs_are_rejected(
    endpoint: Endpoint, users: list[User], mutate: object, message: str
) -> None:
    data = _config_json(endpoint, users[0])
    mutate(data)  # type: ignore[operator]
    with pytest.raises(ConfigError, match=message):
        BrainConfig.from_json(json.dumps(data))
