"""hysteria2 and paqet as first-class Oracle paths (not just a hook)."""

from __future__ import annotations

import json

import pytest

from shahrah.brain import Brain, BrainConfig, Sidecar
from shahrah.models import ConfigError, Endpoint, Profile, User
from shahrah.oracle import Mode, OracleConfig
from shahrah.prober import ProbeResult

FAST = OracleConfig(fail_streak=2, recover_streak=2, min_dwell_s=0, outage_after_cycles=2)
KEY = "A" * 43


def _eps() -> tuple[Endpoint, ...]:
    return (
        Endpoint("a", "a.example.com", 443, Profile.REALITY_VISION, KEY, "ab", "www.example.com"),
        Endpoint("b", "b.example.com", 443, Profile.REALITY_VISION, KEY, "ab", "www.example.com"),
    )


def _cfg(*sidecars: Sidecar) -> BrainConfig:
    return BrainConfig(
        endpoints=_eps(), probe_user=User.create("p"), remarks={}, oracle=FAST, sidecars=sidecars
    )


class Rounds:
    def __init__(self, *rounds: dict[str, bool]) -> None:
        self.rounds = list(rounds)

    def __call__(self) -> list[ProbeResult]:
        cur = self.rounds.pop(0) if len(self.rounds) > 1 else self.rounds[0]
        return [ProbeResult(n, ok, 40.0 if ok else None) for n, ok in cur.items()]


def test_kind_defaults() -> None:
    hy2 = Sidecar("hy2", "hysteria2", 1081)
    pq = Sidecar("paqet", "paqet", 1080)
    assert hy2.lockdown_capable is False and hy2.on_demand is False
    assert pq.lockdown_capable is True and pq.on_demand is True
    with pytest.raises(ConfigError):
        Sidecar("x", "wireguard", 1)


def test_hysteria2_is_ranked_as_its_own_path() -> None:
    brain = Brain(
        _cfg(Sidecar("hy2", "hysteria2", 1081, priority=1)),
        Rounds({"a": False, "b": False, "hy2": True}),
        clock=lambda: 0.0,
    )
    decision = brain.cycle()
    assert decision is not None
    assert decision.ranking == ("hy2",)
    assert decision.state.active == "hy2"


def test_paqet_is_ignored_outside_crisis_and_counts_inside() -> None:
    cfg = _cfg(Sidecar("paqet", "paqet", 1080))
    allowlist = {"a": False, "b": False, "paqet": True}
    calls: list[tuple[Mode, Mode]] = []
    brain = Brain(
        cfg,
        Rounds({"a": True, "b": True, "paqet": False}, *[allowlist] * 8),
        clock=lambda: 0.0,
        on_mode_change=lambda p, c: calls.append((p, c)),
    )
    first = brain.cycle()
    assert first is not None and first.state.mode is Mode.NORMAL  # stopped paqet is not a path
    modes = []
    for _ in range(6):
        d = brain.cycle()
        assert d is not None
        modes.append(d.state.mode)
    # TCP paths die -> outage -> hook starts paqet -> paqet is probed and carries traffic.
    assert Mode.OUTAGE in [cur for _, cur in calls]
    assert calls[-1] == (Mode.OUTAGE, Mode.RESTRICTED)
    assert brain.state.active == "paqet"
    assert modes[-1] is Mode.RESTRICTED


def test_sidecar_names_must_be_unique() -> None:
    with pytest.raises(ConfigError, match="sidecar names"):
        _cfg(Sidecar("a", "hysteria2", 1081))


def test_from_json_reads_sidecars() -> None:
    eps = _eps()
    data = {
        "endpoints": [
            {
                "name": e.name,
                "host": e.host,
                "port": e.port,
                "profile": str(e.profile),
                "public_key": e.public_key,
                "short_id": e.short_id,
                "sni": e.sni,
            }
            for e in eps
        ],
        "probe_user": {"uuid": "11111111-1111-4111-8111-111111111111", "label": "p"},
        "sidecars": [
            {"name": "hy2", "kind": "hysteria2", "socks_port": 1081, "priority": 2},
            {"name": "paqet", "kind": "paqet", "socks_port": 1080},
        ],
    }
    cfg = BrainConfig.from_json(json.dumps(data))
    assert [s.name for s in cfg.sidecars] == ["hy2", "paqet"]
    assert [s.name for s in cfg.specs()] == ["a", "b", "hy2"]
    assert [s.name for s in cfg.specs(crisis=True)] == ["a", "b", "hy2", "paqet"]
