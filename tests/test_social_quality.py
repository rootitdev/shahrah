from __future__ import annotations

import pytest

from shahrah.models import TUNING_PROFILES, ConfigError, Tuning
from shahrah.prober import (
    INSTAGRAM_TARGETS,
    ProbeResult,
    ProbeTarget,
    probe_weighted,
    social_quality,
)
from shahrah.xray_config import _policy_level, _sockopt


def r(ok: bool, ms: float | None = None) -> ProbeResult:
    return ProbeResult("x", ok, ms, "" if ok else "timeout")


def test_weighted_success_and_latency() -> None:
    got = social_quality("p", [(3, r(True, 100)), (1, r(True, 300))])
    assert got.ok and got.endpoint == "p" and got.latency_ms == 150.0


def test_instagram_failure_dominates_generic_success() -> None:
    got = social_quality("p", [(3, r(False)), (2, r(True, 50)), (1, r(True, 50))])
    assert not got.ok and "0.50" in got.detail


def test_threshold_and_errors() -> None:
    assert social_quality("p", [(3, r(True, 10)), (1, r(False))]).ok  # 0.75
    with pytest.raises(ValueError):
        social_quality("p", [])
    with pytest.raises(ValueError):
        social_quality("p", [(1, r(True, 1))], min_score=0)


def test_probe_weighted_hits_every_instagram_target() -> None:
    seen: list[str] = []

    def probe(target: ProbeTarget) -> ProbeResult:
        seen.append(target.host)
        return r(True, 80.0)

    assert probe_weighted("p", probe).ok
    assert seen == [t.target.host for t in INSTAGRAM_TARGETS]
    assert "i.instagram.com" in seen


def test_default_tuning_renders_unchanged_keys() -> None:
    t = Tuning()
    assert set(_sockopt(t)) == {"tcpKeepAliveIdle", "tcpKeepAliveInterval"}
    assert set(_policy_level(t)) == {"handshake", "connIdle", "bufferSize"}


def test_social_profile_renders_documented_xray_keys() -> None:
    social = TUNING_PROFILES["social"]
    opts = _sockopt(social)
    assert opts["tcpFastOpen"] is True
    assert opts["tcpcongestion"] == "bbr"
    assert opts["tcpUserTimeout"] == 10000
    level = _policy_level(social)
    assert level["uplinkOnly"] == 0 and level["downlinkOnly"] == 0


@pytest.mark.parametrize(
    "kwargs",
    [{"tcp_congestion": "x"}, {"tcp_user_timeout_ms": 5}, {"uplink_only_s": 99}],
)
def test_tuning_validation(kwargs: dict) -> None:
    with pytest.raises(ConfigError):
        Tuning(**kwargs)


def test_state_round_trips_tuning_profile() -> None:
    from shahrah.state import NodeState

    state = NodeState.create(public_host="203.0.113.10", target_host="www.example.com")
    social = state.with_tuning_profile("social")
    again = NodeState.from_json(social.to_json())
    assert again.tuning_profile == "social"
    assert again.server_settings().tuning == TUNING_PROFILES["social"]
    with pytest.raises(ConfigError):
        state.with_tuning_profile("turbo")
