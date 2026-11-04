from __future__ import annotations

from pathlib import Path

import pytest

from shahrah import ig_mult
from shahrah.accounting import UserTraffic
from shahrah.models import ConfigError


def test_matches_instagram_suffixes() -> None:
    assert ig_mult.matches_instagram("scontent-foo.cdninstagram.com")
    assert ig_mult.matches_instagram("www.instagram.com")
    assert not ig_mult.matches_instagram("www.example.com")
    assert not ig_mult.matches_instagram("203.0.113.9")


def test_share_and_billing() -> None:
    share = ig_mult.share_from_hits(
        {"www.instagram.com": 3, "api.telegram.org": 1},
        ig_mult.DEFAULT_INSTAGRAM_SUFFIXES,
    )
    assert share == 0.75
    billed = ig_mult.apply_multiplier(UserTraffic("alice", 1000, 2000), share, 0.5)
    # factor = 0.25 + 0.75*0.5 = 0.625
    assert billed.billed_up == 625
    assert billed.billed_down == 1250


def test_disabled_means_raw_equals_billed() -> None:
    raw = {"alice": UserTraffic("alice", 10, 20)}
    hits = {"alice": {"www.instagram.com": 100}}
    out = ig_mult.bill_users(raw, hits, ig_mult.IgMultConfig(enabled=False, coefficient=0.1))
    assert out["alice"].billed_up == 10
    assert out["alice"].share == 0.0


def test_config_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "ig.json"
    cfg = ig_mult.IgMultConfig(enabled=True, coefficient=0.5)
    ig_mult.save_config(path, cfg)
    loaded = ig_mult.load_config(path)
    assert loaded.enabled is True
    assert loaded.coefficient == 0.5
    assert "instagram.com" in loaded.suffixes


def test_bad_coefficient_rejected() -> None:
    with pytest.raises(ConfigError, match="coefficient"):
        ig_mult.IgMultConfig(coefficient=11)


def test_state_estimate_without_log(tmp_path: Path) -> None:
    state = ig_mult.IgMultState(config_path=tmp_path / "ig.json")
    state.update(ig_mult.IgMultConfig(enabled=True, coefficient=0.5))
    report = state.estimate({"bob": UserTraffic("bob", 100, 100)})
    assert report["users"]["bob"]["billed_uplink"] == 100  # no hits -> share 0
    assert report["config"]["enabled"] is True
