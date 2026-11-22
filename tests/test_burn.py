from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from shahrah import vantage
from shahrah.brain import Brain, BrainConfig
from shahrah.burn import BurnConfig, BurnState, Verdict, classify, step
from shahrah.models import Endpoint, User
from shahrah.oracle import OracleConfig
from shahrah.prober import ProbeResult

CFG = BurnConfig(burn_after=3, recover_after=2)


def run(rounds: list[tuple[dict[str, bool], dict[str, bool]]], cfg: BurnConfig = CFG):
    state, decisions = BurnState(), []
    for field_results, control in rounds:
        decision = step(cfg, state, field_results, control)
        state = decision.state
        decisions.append(decision)
    return decisions


def test_classification_table() -> None:
    assert classify(True, None) is Verdict.HEALTHY
    assert classify(True, False) is Verdict.HEALTHY
    assert classify(False, True) is Verdict.BLOCKED
    assert classify(False, False) is Verdict.DOWN
    assert classify(False, None) is Verdict.UNKNOWN


def test_burn_needs_consecutive_blocked_cycles() -> None:
    blocked = ({"a": False, "b": True}, {"a": True, "b": True})
    decisions = run([blocked, blocked, blocked])
    assert [d.newly_burned for d in decisions] == [(), (), ("a",)]
    assert decisions[-1].state.burned == ("a",)


def test_transient_loss_resets_the_streak() -> None:
    blocked = ({"a": False, "b": True}, {"a": True, "b": True})
    fine = ({"a": True, "b": True}, {"a": True, "b": True})
    decisions = run([blocked, blocked, fine, blocked, blocked])
    assert all(d.newly_burned == () for d in decisions)


def test_a_server_that_is_down_everywhere_is_not_burned() -> None:
    down = ({"a": False, "b": True}, {"a": False, "b": True})
    decisions = run([down] * 6)
    assert all(d.newly_burned == () for d in decisions)
    assert decisions[-1].verdicts["a"] is Verdict.DOWN


def test_never_declare_a_burn_without_control_information() -> None:
    blind = ({"a": False, "b": True}, {})
    assert all(d.newly_burned == () for d in run([blind] * 10))


def test_network_wide_block_is_not_a_burn_and_holds_streaks() -> None:
    everything = ({"a": False, "b": False}, {"a": True, "b": True})
    decisions = run([everything] * 5)
    assert all(d.network_wide and d.newly_burned == () for d in decisions)


def test_single_endpoint_blocked_can_still_burn() -> None:
    only = ({"a": False}, {"a": True})
    assert run([only] * 3)[-1].newly_burned == ("a",)


def test_burn_is_forgiven_after_sustained_recovery() -> None:
    blocked = ({"a": False, "b": True}, {"a": True, "b": True})
    fine = ({"a": True, "b": True}, {"a": True, "b": True})
    decisions = run([blocked] * 3 + [fine, fine])
    assert decisions[3].state.burned == ("a",)  # one good cycle is not enough
    assert decisions[4].recovered == ("a",) and decisions[4].state.burned == ()


def test_burned_is_reported_only_once() -> None:
    blocked = ({"a": False, "b": True}, {"a": True, "b": True})
    decisions = run([blocked] * 6)
    assert sum(len(d.newly_burned) for d in decisions) == 1


def test_config_validation() -> None:
    with pytest.raises(ValueError, match=">= 1"):
        BurnConfig(burn_after=0)


# --- vantage reports -------------------------------------------------------------------


def results(**kw: bool) -> list[ProbeResult]:
    return [ProbeResult(n, ok, 10.0 if ok else None, "") for n, ok in kw.items()]


def test_report_round_trip_through_a_file(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "report.json"
    vantage.write_report(path, vantage.build_report(results(a=True, b=False), now=1000.0))
    fetch = vantage.make_control_source(str(path), clock=lambda: 1100.0)
    assert fetch() == {"a": True, "b": False}
    assert list(path.parent.iterdir()) == [path]  # no temp file left behind


def test_stale_malformed_or_missing_reports_yield_no_information(tmp_path: Path) -> None:
    path = tmp_path / "r.json"
    vantage.write_report(path, vantage.build_report(results(a=True), now=0.0))
    assert vantage.make_control_source(str(path), max_age_s=60, clock=lambda: 500.0)() == {}
    path.write_text("not json", encoding="utf-8")
    assert vantage.make_control_source(str(path))() == {}
    assert vantage.make_control_source(str(tmp_path / "missing.json"))() == {}


def test_future_dated_report_is_rejected() -> None:
    text = json.dumps({"version": 1, "generated_at": 10_000, "results": {"a": True}})
    with pytest.raises(vantage.VantageError, match="future"):
        vantage.parse_report(text, now=0.0, max_age_s=60)


@pytest.mark.parametrize(
    "text",
    [
        json.dumps({"version": 2, "generated_at": 0, "results": {}}),
        json.dumps({"version": 1, "generated_at": 0, "results": {"a": "yes"}}),
        json.dumps({"version": 1, "generated_at": 0, "results": [True]}),
        json.dumps({"version": 1, "results": {}}),
    ],
)
def test_malformed_reports_are_rejected(text: str) -> None:
    with pytest.raises(vantage.VantageError):
        vantage.parse_report(text, now=0.0, max_age_s=60)


def test_plain_http_control_url_is_refused() -> None:
    assert vantage.make_control_source("http://example.invalid/r.json")() == {}


# --- brain integration -----------------------------------------------------------------


@pytest.fixture
def config(endpoint: Endpoint, users: list[User]) -> BrainConfig:
    a = replace(endpoint, name="exit-a", priority=0)
    b = replace(endpoint, name="exit-b", priority=1)
    return BrainConfig(
        endpoints=(a, b),
        probe_user=users[0],
        remarks={},
        oracle=OracleConfig(fail_streak=1, recover_streak=1, min_dwell_s=0),
        burn=BurnConfig(burn_after=2, recover_after=2),
    )


def probe_round() -> list[ProbeResult]:
    return results(**{"exit-a": False, "exit-b": True})


def test_brain_calls_the_hook_once_when_a_path_is_burned(config: BrainConfig) -> None:
    calls: list[tuple[str, ...]] = []
    brain = Brain(
        config,
        probe_round,
        control_source=lambda: {"exit-a": True, "exit-b": True},
        on_burn=lambda names: calls.append(tuple(names)),
    )
    for _ in range(4):
        brain.cycle()
    assert calls == [("exit-a",)]
    assert brain.burned == ("exit-a",)


def test_a_crashing_hook_does_not_stop_the_loop(config: BrainConfig) -> None:
    def explode(names: object) -> None:
        raise RuntimeError("boom")

    brain = Brain(
        config,
        probe_round,
        control_source=lambda: {"exit-a": True, "exit-b": True},
        on_burn=explode,
    )
    for _ in range(3):
        assert brain.cycle() is not None


def test_without_control_source_burn_detection_is_off(config: BrainConfig) -> None:
    calls: list[object] = []
    brain = Brain(config, probe_round, on_burn=calls.append)
    for _ in range(5):
        brain.cycle()
    assert calls == [] and brain.burned == ()


def test_report_sink_receives_every_round_and_failures_are_contained(config: BrainConfig) -> None:
    seen: list[int] = []

    def sink(rs: object) -> None:
        seen.append(len(rs))  # type: ignore[arg-type]
        raise OSError("disk full")

    brain = Brain(config, probe_round, report_sink=sink)
    brain.cycle()
    brain.cycle()
    assert seen == [2, 2]
