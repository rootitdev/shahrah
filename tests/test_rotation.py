from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import replace

import pytest

from shahrah.brain import Brain, BrainConfig
from shahrah.burn import BurnConfig
from shahrah.models import ConfigError, Endpoint, User
from shahrah.oracle import OracleConfig
from shahrah.panel import SyncPlan
from shahrah.prober import ProbeResult
from shahrah.rotation import serving_ranking

# --- pure function -----------------------------------------------------------------------


def test_spares_stay_hidden_while_everything_is_fine() -> None:
    assert serving_ranking(["a", "b", "s1"], ["s1"], burned=[]) == ("a", "b")


def test_one_spare_is_promoted_per_burned_endpoint() -> None:
    assert serving_ranking(["b", "s1", "s2"], ["s1", "s2"], burned=["a"]) == ("b", "s1")
    assert serving_ranking(["s1", "s2"], ["s1", "s2"], burned=["a", "b"]) == ("s1", "s2")


def test_spares_are_promoted_in_configured_order_not_rank_order() -> None:
    assert serving_ranking(["s2", "s1"], ["s1", "s2"], burned=["a"]) == ("s1",)


def test_unhealthy_spares_cannot_be_promoted() -> None:
    assert serving_ranking(["b"], ["s1"], burned=["a"]) == ("b",)


def test_spare_takes_over_when_no_active_endpoint_is_healthy() -> None:
    assert serving_ranking(["s1", "s2"], ["s1", "s2"], burned=[]) == ("s1",)
    assert serving_ranking([], ["s1"], burned=[]) == ()


# --- brain integration -------------------------------------------------------------------


@pytest.fixture
def config(endpoint: Endpoint, users: list[User]) -> BrainConfig:
    eps = tuple(
        replace(endpoint, name=name, priority=i) for i, name in enumerate(["a", "b", "spare"])
    )
    return BrainConfig(
        endpoints=eps,
        probe_user=users[0],
        remarks={"a": "A", "b": "B", "spare": "S"},
        oracle=OracleConfig(fail_streak=1, recover_streak=1, min_dwell_s=0),
        burn=BurnConfig(burn_after=2, recover_after=2),
        standby=("spare",),
    )


class Panel:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, ranking: Sequence[str]) -> SyncPlan:
        self.calls.append(tuple(ranking))
        return SyncPlan()


def probes(**ok: bool):
    def run() -> list[ProbeResult]:
        return [ProbeResult(n, v, 10.0 if v else None, "") for n, v in ok.items()]

    return run


def test_spare_is_offered_only_after_a_burn(config: BrainConfig) -> None:
    panel = Panel()
    field = probes(a=False, b=True, spare=True)  # "a" is unreachable inside the country
    control = {"a": True, "b": True, "spare": True}
    brain = Brain(config, field, panel, control_source=lambda: control)
    for _ in range(4):
        brain.cycle()
    assert panel.calls[0] == ("b",)  # while "a" is merely suspect, the spare stays hidden
    assert panel.calls[-1] == ("b", "spare")
    assert brain.burned == ("a",)


def test_spare_is_demoted_again_when_the_burn_is_forgiven(config: BrainConfig) -> None:
    panel = Panel()
    state = {"a": False}

    def field() -> list[ProbeResult]:
        return [
            ProbeResult("a", state["a"], 10.0 if state["a"] else None, ""),
            ProbeResult("b", True, 10.0, ""),
            ProbeResult("spare", True, 10.0, ""),
        ]

    control = {"a": True, "b": True, "spare": True}
    brain = Brain(config, field, panel, control_source=lambda: control)
    for _ in range(3):
        brain.cycle()
    assert panel.calls[-1] == ("b", "spare")
    state["a"] = True
    for _ in range(4):
        brain.cycle()
    assert panel.calls[-1] == ("a", "b")
    assert brain.burned == ()


def test_plain_failover_to_a_spare_without_control_information(config: BrainConfig) -> None:
    panel = Panel()
    brain = Brain(config, probes(a=False, b=False, spare=True), panel)
    brain.cycle()
    assert panel.calls[-1] == ("spare",)


# --- config ------------------------------------------------------------------------------


def test_standby_validation(config: BrainConfig) -> None:
    with pytest.raises(ConfigError, match="unknown"):
        replace(config, standby=("ghost",))
    with pytest.raises(ConfigError, match="non-standby"):
        replace(config, standby=("a", "b", "spare"))
    with pytest.raises(ConfigError, match="unique"):
        replace(config, standby=("spare", "spare"))


def test_standby_is_read_from_json(
    config: BrainConfig, endpoint: Endpoint, users: list[User]
) -> None:
    def item(name: str) -> dict[str, object]:
        return {
            "name": name,
            "host": endpoint.host,
            "port": endpoint.port,
            "profile": "reality-vision",
            "public_key": endpoint.public_key,
            "short_id": endpoint.short_id,
            "sni": endpoint.sni,
        }

    text = json.dumps(
        {
            "endpoints": [item("a"), item("spare")],
            "probe_user": {"uuid": users[0].uuid, "label": users[0].label},
            "standby": ["spare"],
        }
    )
    assert BrainConfig.from_json(text).standby == ("spare",)
