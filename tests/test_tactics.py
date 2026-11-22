from __future__ import annotations

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from shahrah import subserve, tactics
from shahrah.cli import main
from shahrah.models import ConfigError, Endpoint, Profile
from shahrah.oracle import Mode
from shahrah.state import NodeState, save_state
from shahrah.tactics import TacticsBundle, TacticsProfile, Transport

KEY = b"k" * 32
PBK = "A" * 43
MCI = 197207  # example ASN used only as a lookup key in tests


def _bundle(serial: int = 2) -> TacticsBundle:
    return TacticsBundle(
        serial=serial,
        issued_at=1000,
        expires_at=2000,
        profiles=(
            TacticsProfile(
                "mobile-restricted",
                Mode.RESTRICTED,
                asns=(MCI,),
                transports=(Transport.DOMESTIC_RELAY, Transport.PAQET),
                ports=(443, 53),
                sni_allowlist=("www.example.ir",),
                entry_hosts=("relay.example.ir",),
                paqet=True,
            ),
        ),
    )


def test_select_prefers_asn_then_generic_then_builtin() -> None:
    profiles = _bundle().profiles
    assert tactics.select(profiles, Mode.RESTRICTED, MCI).name == "mobile-restricted"
    assert tactics.select(profiles, Mode.RESTRICTED, 1).name == "default-restricted"
    assert tactics.select(profiles, Mode.NORMAL, MCI).name == "default-normal"
    assert tactics.select((), Mode.OUTAGE).paqet


def test_profile_validation() -> None:
    with pytest.raises(ConfigError):
        TacticsProfile("x", Mode.NORMAL, paqet=True)
    with pytest.raises(ConfigError):
        TacticsProfile("x", Mode.NORMAL, ports=(443, 443))
    with pytest.raises(ConfigError):
        TacticsProfile("x", Mode.NORMAL, asns=(0,))
    with pytest.raises(ConfigError):
        TacticsProfile.from_dict({"name": "x", "mode": "nope", "transports": []})


def test_round_trip_dict() -> None:
    profile = _bundle().profiles[0]
    assert TacticsProfile.from_dict(json.loads(json.dumps(profile.to_dict()))) == profile


def test_sign_and_verify() -> None:
    env = tactics.sign(_bundle(), KEY, "k1")
    assert tactics.verify(env, {"k1": KEY}, now=1500) == _bundle()


@pytest.mark.parametrize(
    ("mutate", "kwargs", "message"),
    [
        (lambda e: e.update(sig="0" * 64), {}, "signature"),
        (lambda e: e.update(kid="k2"), {}, "unknown"),
        (lambda e: e.update(v=9), {}, "version"),
        (lambda e: None, {"now": 2500}, "expired"),
        (lambda e: None, {"now": 100}, "future"),
        (lambda e: None, {"min_serial": 3}, "replay"),
    ],
)
def test_verify_rejects(mutate, kwargs, message) -> None:
    env = tactics.sign(_bundle(), KEY, "k1")
    mutate(env)
    args = {"now": 1500, **kwargs}
    with pytest.raises(ConfigError, match=message):
        tactics.verify(env, {"k1": KEY}, **args)


def test_tampered_payload_is_rejected() -> None:
    env = tactics.sign(_bundle(), KEY, "k1")
    other = tactics.sign(_bundle(serial=9), KEY, "k1")
    env["payload"] = other["payload"]
    with pytest.raises(ConfigError, match="signature"):
        tactics.verify(env, {"k1": KEY}, now=1500)


def test_short_key_refused() -> None:
    with pytest.raises(ConfigError):
        tactics.sign(_bundle(), b"short", "k1")


def _ep(name: str, host: str, port: int, profile: Profile, priority: int = 0) -> Endpoint:
    if profile is Profile.CDN_XHTTP:
        return Endpoint(name, host, port, profile, sni=host, xhttp_mode="packet-up")
    return Endpoint(name, host, port, profile, PBK, "ab", "www.example.com", priority=priority)


def test_order_endpoints_follows_profile() -> None:
    eps = [
        _ep("vision", "exit.example.com", 443, Profile.REALITY_VISION),
        _ep("x53", "exit.example.com", 53, Profile.REALITY_XHTTP),
        _ep("x80", "exit.example.com", 80, Profile.REALITY_XHTTP),
        _ep("relay", "relay.example.ir", 443, Profile.REALITY_XHTTP),
        _ep("cdn", "cdn.example.com", 443, Profile.CDN_XHTTP),
    ]
    restricted = tactics.select((), Mode.RESTRICTED)
    restricted = TacticsProfile(
        restricted.name,
        restricted.mode,
        transports=restricted.transports,
        entry_hosts=("relay.example.ir",),
        paqet=True,
    )
    names = [e.name for e in tactics.order_endpoints(eps, restricted)]
    assert names == ["relay", "x80", "x53", "cdn"]  # vision dropped, 443/80/53 port order
    normal = [e.name for e in tactics.order_endpoints(eps, tactics.select((), Mode.NORMAL))]
    assert normal[0] == "vision"


def test_tactics_sign_cli_and_subscription_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    profiles = tmp_path / "p.json"
    profiles.write_text(json.dumps([p.to_dict() for p in _bundle().profiles]))
    out = tmp_path / "tactics.json"
    monkeypatch.setenv("SHAHRAH_TACTICS_KEY", KEY.hex())
    assert main(["tactics-sign", str(profiles), "--serial", "5", "--out", str(out)]) == 0
    env = json.loads(out.read_text())
    import time

    assert tactics.verify(env, {"k1": KEY}, now=time.time()).serial == 5

    state_path = tmp_path / "state.json"
    state = NodeState.create(public_host="203.0.113.10", target_host="www.example.com")
    state, _ = state.with_user("alice")
    save_state(state_path, state)
    handler = subserve.make_handler(state_path, "s" * 16, out)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        url = f"http://127.0.0.1:{port}/{'s' * 16}/alice/tactics"
        with opener.open(url, timeout=3) as response:
            assert json.loads(response.read()) == env
    finally:
        server.shutdown()
