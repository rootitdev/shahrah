from __future__ import annotations

from dataclasses import replace

import pytest

from shahrah.models import (
    ConfigError,
    Endpoint,
    Profile,
    RealityServer,
    ServerSettings,
    User,
)
from tests.conftest import FAKE_KEY


def test_reality_defaults_server_names_to_target(reality: RealityServer) -> None:
    assert reality.server_names == ("www.example.com",)


@pytest.mark.parametrize("target", ["www.apple.com", "icloud.com", "a.mzstatic.com"])
def test_risky_reality_targets_are_refused(target: str) -> None:
    with pytest.raises(ConfigError, match="blocked"):
        RealityServer(target_host=target, private_key=FAKE_KEY, short_ids=("ab",))


def test_risky_target_can_be_forced() -> None:
    RealityServer(
        target_host="www.apple.com",
        private_key=FAKE_KEY,
        short_ids=("ab",),
        allow_risky_target=True,
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"target_host": "203.0.113.5"},  # IP target
        {"target_host": "Not_A_Domain"},
        {"private_key": "short"},
        {"short_ids": ()},
        {"short_ids": ("xyz",)},
        {"short_ids": ("abc",)},  # odd length
        {"target_port": 0},
    ],
)
def test_reality_rejects_bad_values(kwargs: dict) -> None:
    base = {"target_host": "www.example.com", "private_key": FAKE_KEY, "short_ids": ("ab",)}
    with pytest.raises(ConfigError):
        RealityServer(**{**base, **kwargs})


def test_non_443_is_refused_unless_explicit(reality: RealityServer) -> None:
    with pytest.raises(ConfigError, match="443"):
        ServerSettings(profile=Profile.REALITY_VISION, reality=reality, port=8443)
    ServerSettings(profile=Profile.REALITY_VISION, reality=reality, port=8443, allow_non_443=True)


def test_stats_port_must_differ_from_public_port(reality: RealityServer) -> None:
    with pytest.raises(ConfigError):
        ServerSettings(profile=Profile.REALITY_VISION, reality=reality, stats_api_port=443)


def test_xhttp_validation(reality: RealityServer) -> None:
    with pytest.raises(ConfigError):
        ServerSettings(profile=Profile.REALITY_XHTTP, reality=reality, xhttp_path="no-slash")
    with pytest.raises(ConfigError):
        ServerSettings(profile=Profile.REALITY_XHTTP, reality=reality, xhttp_mode="bogus")


def test_user_validation_and_canonical_uuid() -> None:
    user = User("11111111-1111-4111-8111-11111111111A", "ok.label")
    assert user.uuid == "11111111-1111-4111-8111-11111111111a"
    with pytest.raises(ConfigError):
        User("not-a-uuid", "label")
    with pytest.raises(ConfigError):
        User("11111111-1111-4111-8111-111111111111", "bad label!")


def test_user_create_generates_unique_ids() -> None:
    assert User.create("a").uuid != User.create("a").uuid


def test_endpoint_validation(endpoint: Endpoint) -> None:
    assert endpoint.host == "203.0.113.10"
    for bad in ({"host": "bad host"}, {"port": 70000}, {"short_id": "zz"}, {"name": " "}):
        with pytest.raises(ConfigError):
            replace(endpoint, **bad)
