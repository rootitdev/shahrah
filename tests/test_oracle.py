from __future__ import annotations

import pytest

from shahrah.oracle import (
    Decision,
    Mode,
    OracleConfig,
    OracleState,
    PathSpec,
    Probe,
    step,
)

CFG = OracleConfig(fail_streak=3, recover_streak=5, min_dwell_s=120, outage_after_cycles=3)
SPECS = [
    PathSpec("direct", priority=0),
    PathSpec("cdn", priority=1, lockdown_capable=True),
    PathSpec("backup", priority=2, lockdown_capable=True),
]


def run(
    state: OracleState,
    cycles: list[dict[str, bool | float]],
    *,
    start: float = 0.0,
    every: float = 12.0,
) -> tuple[OracleState, list[Decision]]:
    """Feed probe cycles; a float value means ok with that latency, bool is plain ok/fail."""
    decisions: list[Decision] = []
    for i, cycle in enumerate(cycles):
        probes = [
            Probe(name, ok=bool(value), latency_ms=value if isinstance(value, float) else None)
            for name, value in cycle.items()
        ]
        decision = step(CFG, state, SPECS, probes, now=start + i * every)
        state = decision.state
        decisions.append(decision)
    return state, decisions


ALL_OK = {"direct": True, "cdn": True, "backup": True}


def test_first_cycle_picks_highest_priority() -> None:
    _, [d] = run(OracleState(), [ALL_OK])
    assert d.state.active == "direct"
    assert d.switched and d.reason == "initial selection"
    assert d.ranking == ("direct", "cdn", "backup")
    assert d.state.mode is Mode.NORMAL


def test_never_working_path_is_trusted_after_one_success_only() -> None:
    _, [d1, d2] = run(
        OracleState(), [{"direct": False, "cdn": True}, {"direct": True, "cdn": True}]
    )
    assert d1.ranking == ("cdn",)
    assert d2.ranking == ("direct", "cdn")  # one success was enough: it never worked before


def test_leaves_failed_path_immediately_after_fail_streak() -> None:
    down = {"direct": False, "cdn": True, "backup": True}
    state, decisions = run(OracleState(), [ALL_OK, down, down, down])
    assert [d.state.active for d in decisions] == ["direct", "direct", "direct", "cdn"]
    assert decisions[-1].switched and "direct unhealthy" in decisions[-1].reason
    # direct was the only ordinary path, so this already looks like allowlist filtering
    assert state.mode is Mode.RESTRICTED


def test_alternating_failures_do_not_flap() -> None:
    flaky = [ALL_OK, {**ALL_OK, "direct": False}] * 6
    state, decisions = run(OracleState(), flaky)
    assert {d.state.active for d in decisions} == {"direct"}
    assert not any(d.switched for d in decisions[1:])
    assert state.mode is Mode.NORMAL  # a single failure never reaches the fail streak


def test_failback_needs_recover_streak_and_dwell() -> None:
    down = {"direct": False, "cdn": True, "backup": True}
    state, _ = run(OracleState(), [ALL_OK, down, down, down])
    assert state.active == "cdn"
    # direct recovers: 4 oks are not enough (needs 5), even long after the dwell time
    state, ds = run(state, [ALL_OK] * 4, start=1000.0)
    assert state.active == "cdn" and not any(d.switched for d in ds)
    # 5th consecutive ok makes it healthy and dwell is satisfied -> failback
    state, [d] = run(state, [ALL_OK], start=2000.0)
    assert d.switched and d.state.active == "direct"
    assert "failback" in d.reason


def test_failback_waits_for_min_dwell() -> None:
    down = {"direct": False, "cdn": True, "backup": True}
    state, _ = run(OracleState(), [ALL_OK, down, down, down])
    # direct is healthy again, but only seconds after we moved: stay on cdn (dwell is 120s)
    state, decisions = run(state, [ALL_OK] * 5, start=state.active_since + 1.0, every=1.0)
    assert state.active == "cdn"
    assert not any(d.switched for d in decisions)
    assert decisions[-1].ranking[0] == "direct"  # healthy and preferred, just not yet adopted


def test_latency_switch_requires_significant_gain_same_priority() -> None:
    specs = [PathSpec("a", priority=0), PathSpec("b", priority=0)]
    state = OracleState()
    d = step(CFG, state, specs, [Probe("a", True, 100.0), Probe("b", True, 90.0)], now=0.0)
    assert d.state.active == "b"  # tie on priority -> lower latency wins initially
    state = d.state
    # a becomes only slightly faster: no switch
    d = step(CFG, state, specs, [Probe("a", True, 85.0)], now=500.0)
    assert d.state.active == "b" and not d.switched


def test_outage_after_consecutive_empty_cycles_and_recovery() -> None:
    dead = {"direct": False, "cdn": False, "backup": False}
    state, decisions = run(OracleState(), [ALL_OK] + [dead] * 8)
    assert state.mode is Mode.OUTAGE
    assert state.active == "direct"  # nothing healthier to move to: keep last known path
    assert decisions[-1].reason == "no healthy path"
    # service returns: 5 consecutive oks restore health and clear the outage
    state, _ = run(state, [ALL_OK] * 5, start=1000.0)
    assert state.mode is Mode.NORMAL and state.down_cycles == 0


def test_restricted_mode_when_only_lockdown_capable_paths_survive() -> None:
    allowlist = {"direct": False, "cdn": True, "backup": True}
    state, _ = run(OracleState(), [ALL_OK] + [allowlist] * 3)
    assert state.mode is Mode.RESTRICTED


def test_single_server_outage_is_degraded_not_restricted() -> None:
    specs = [
        PathSpec("direct-1", priority=0),
        PathSpec("direct-2", priority=0),
        PathSpec("cdn", priority=1, lockdown_capable=True),
    ]
    probes = [Probe("direct-1", True), Probe("direct-2", True), Probe("cdn", True)]
    state = step(CFG, OracleState(), specs, probes, now=0.0).state
    one_down = [Probe("direct-1", False), Probe("direct-2", True), Probe("cdn", True)]
    both_down = [Probe("direct-1", False), Probe("direct-2", False), Probe("cdn", True)]
    for i in range(3):
        state = step(CFG, state, specs, one_down, now=12.0 * (i + 1)).state
    assert state.mode is Mode.DEGRADED
    for i in range(3):
        state = step(CFG, state, specs, both_down, now=100.0 + 12.0 * i).state
    assert state.mode is Mode.RESTRICTED


def test_cdn_failure_alone_is_degraded() -> None:
    state, _ = run(OracleState(), [ALL_OK] + [{**ALL_OK, "cdn": False}] * 3)
    assert state.mode is Mode.DEGRADED


def test_unknown_probe_path_is_a_configuration_error() -> None:
    with pytest.raises(ValueError, match="unknown path"):
        step(CFG, OracleState(), SPECS, [Probe("ghost", True)], now=0.0)


def test_invalid_config_is_rejected() -> None:
    for bad in ({"fail_streak": 0}, {"ewma_alpha": 0.0}, {"latency_switch_ratio": 1.5}):
        with pytest.raises(ValueError):
            OracleConfig(**bad)
