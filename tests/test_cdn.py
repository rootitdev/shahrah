from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from shahrah.cli import _parse_listener, main
from shahrah.links import vless_link
from shahrah.models import (
    ConfigError,
    Endpoint,
    Listener,
    Profile,
    RealityServer,
    ServerSettings,
    User,
)
from shahrah.state import NodeState
from shahrah.xray_client import render_probe_config
from shahrah.xray_config import render_server_config

PATH = "/s3cret-path-123"


def cdn_listener(**kw: object) -> Listener:
    base = {
        "port": 8080,
        "profile": Profile.CDN_XHTTP,
        "xhttp_path": PATH,
        "xhttp_mode": "packet-up",
        "cdn_host": "cdn.example.com",
    }
    return Listener(**{**base, **kw})  # type: ignore[arg-type]


def cdn_endpoint(**kw: object) -> Endpoint:
    base = {
        "name": "cdn",
        "host": "cdn.example.com",
        "port": 443,
        "profile": Profile.CDN_XHTTP,
        "sni": "cdn.example.com",
        "xhttp_path": PATH,
        "xhttp_mode": "packet-up",
    }
    return Endpoint(**{**base, **kw})  # type: ignore[arg-type]


# --- validation ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kw", "message"),
    [
        ({"cdn_host": ""}, "cdn_host"),
        ({"cdn_host": "203.0.113.5"}, "cdn_host"),
        ({"xhttp_mode": "stream-one"}, "behind a CDN"),
        ({"xhttp_path": "/"}, "unguessable"),
        ({"xhttp_path": "/short"}, "unguessable"),
    ],
)
def test_cdn_listener_rejects_unsafe_values(kw: dict[str, object], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        cdn_listener(**kw)


def test_cdn_host_is_rejected_on_reality_listeners() -> None:
    with pytest.raises(ConfigError, match="only valid"):
        Listener(443, Profile.REALITY_VISION, cdn_host="cdn.example.com")


def test_primary_listener_cannot_be_cdn(reality: RealityServer) -> None:
    with pytest.raises(ConfigError, match="primary"):
        ServerSettings(
            profile=Profile.CDN_XHTTP, reality=reality, xhttp_path=PATH, xhttp_mode="packet-up"
        )


def test_cdn_endpoint_rules() -> None:
    assert cdn_endpoint().tls
    with pytest.raises(ConfigError, match="no REALITY"):
        cdn_endpoint(public_key="A" * 43)
    with pytest.raises(ConfigError, match="sni"):
        cdn_endpoint(tls=False)  # sni set but no TLS
    with pytest.raises(ConfigError, match="must not be"):
        cdn_endpoint(xhttp_mode="stream-one")
    assert not cdn_endpoint(tls=False, sni="", port=80).tls


def test_reality_endpoints_still_require_their_keys() -> None:
    with pytest.raises(ConfigError, match="public key"):
        Endpoint("x", "203.0.113.1", 443, Profile.REALITY_VISION, sni="www.example.com")


# --- server config ---------------------------------------------------------------------


def test_server_config_has_a_plain_xhttp_inbound_without_vision_flow(
    reality: RealityServer, users: list[User]
) -> None:
    server = ServerSettings(
        profile=Profile.REALITY_VISION,
        reality=reality,
        allow_non_443=True,
        extra_listeners=(cdn_listener(),),
    )
    inbounds = render_server_config(server, users)["inbounds"]
    main_in, cdn_in = inbounds
    assert main_in["streamSettings"]["security"] == "reality"
    assert cdn_in["tag"] == "in-8080"
    assert cdn_in["streamSettings"]["security"] == "none"
    assert cdn_in["streamSettings"]["network"] == "xhttp"
    assert cdn_in["streamSettings"]["xhttpSettings"] == {"path": PATH, "mode": "packet-up"}
    assert all("flow" not in c for c in cdn_in["settings"]["clients"])
    assert "realitySettings" not in cdn_in["streamSettings"]


# --- links and clients -----------------------------------------------------------------


def test_cdn_link_uses_tls_to_the_edge(users: list[User]) -> None:
    parts = urlsplit(vless_link(cdn_endpoint(), users[0]))
    query = parse_qs(parts.query)
    assert parts.hostname == "cdn.example.com" and parts.port == 443
    assert query["security"] == ["tls"] and query["sni"] == ["cdn.example.com"]
    assert query["type"] == ["xhttp"] and query["path"] == [PATH]
    assert "pbk" not in query and "flow" not in query


def test_plain_edge_link_has_no_tls_parameters(users: list[User]) -> None:
    link = vless_link(cdn_endpoint(tls=False, sni="", port=80), users[0])
    query = parse_qs(urlsplit(link).query)
    assert query["security"] == ["none"] and "sni" not in query and "fp" not in query


def test_probe_config_for_cdn_endpoint(users: list[User]) -> None:
    config = render_probe_config(
        [cdn_endpoint(), cdn_endpoint(name="plain", tls=False, sni="", port=80)],
        users[0],
        [20001, 20002],
    )
    tls_stream, plain_stream = (o["streamSettings"] for o in config["outbounds"])
    assert tls_stream["security"] == "tls"
    assert tls_stream["tlsSettings"]["serverName"] == "cdn.example.com"
    assert plain_stream["security"] == "none" and "tlsSettings" not in plain_stream
    assert tls_stream["xhttpSettings"]["path"] == PATH


def test_real_xray_accepts_server_and_client_configs(
    xray_bin: str, reality: RealityServer, users: list[User], tmp_path: Path, real_private_key: str
) -> None:
    server = ServerSettings(
        profile=Profile.REALITY_VISION,
        reality=replace(reality, private_key=real_private_key),
        allow_non_443=True,
        extra_listeners=(cdn_listener(),),
    )
    client = render_probe_config([cdn_endpoint()], users[0], [20001])
    for name, config in (
        ("server", render_server_config(server, users)),
        ("client", client),
    ):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        result = subprocess.run(
            [xray_bin, "run", "-test", "-c", str(path)], capture_output=True, text=True, check=False
        )
        assert result.returncode == 0, f"{name}: {result.stdout}{result.stderr}"


# --- state and CLI ---------------------------------------------------------------------


def test_state_round_trips_cdn_listeners_and_derives_edge_endpoints() -> None:
    state = NodeState.create(
        public_host="203.0.113.10",
        target_host="www.example.com",
        allow_non_443=True,
        extra_listeners=(cdn_listener(), cdn_listener(port=80, edge_tls=False)),
    )
    again = NodeState.from_json(state.to_json())
    assert again.extra_listeners == state.extra_listeners
    by_name = {e.name: e for e in again.endpoints()}
    assert by_name["main-443"].profile is Profile.REALITY_VISION
    tls_edge, plain_edge = by_name["main-cdn-8080"], by_name["main-cdn-80"]
    assert (tls_edge.host, tls_edge.port, tls_edge.tls) == ("cdn.example.com", 443, True)
    assert (plain_edge.port, plain_edge.tls, plain_edge.sni) == (80, False, "")
    assert tls_edge.priority > by_name["main-53"].priority if "main-53" in by_name else True
    assert tls_edge.lockdown_capable and not by_name["main-443"].lockdown_capable


def test_old_state_without_cdn_fields_still_loads() -> None:
    state = NodeState.create(public_host="203.0.113.10", target_host="www.example.com")
    data = json.loads(state.to_json())
    data["listeners"] = [
        {"port": 80, "profile": "reality-xhttp", "xhttp_path": "/", "xhttp_mode": "stream-one"}
    ]
    assert NodeState.from_json(json.dumps(data)).extra_listeners[0].profile is (
        Profile.REALITY_XHTTP
    )


def test_listener_spec_parsing() -> None:
    plain = _parse_listener("80:reality-xhttp")
    assert plain == Listener(80, Profile.REALITY_XHTTP)
    generated = _parse_listener("8080:cdn-xhttp:cdn.example.com")
    assert generated.cdn_host == "cdn.example.com" and generated.edge_tls
    assert generated.xhttp_mode == "packet-up" and len(generated.xhttp_path) >= 9
    assert generated.xhttp_path != _parse_listener("8080:cdn-xhttp:cdn.example.com").xhttp_path
    fixed = _parse_listener("8080:cdn-xhttp:cdn.example.com:my-secret-path:http")
    assert fixed.xhttp_path == "/my-secret-path" and not fixed.edge_tls
    with pytest.raises(ConfigError):
        _parse_listener("8080:cdn-xhttp")  # host missing
    with pytest.raises(ConfigError, match="scheme"):
        _parse_listener("8080:cdn-xhttp:cdn.example.com:p:ftp")
    with pytest.raises(ConfigError):
        _parse_listener("443:reality-vision:oops")


def test_cli_adds_a_cdn_listener_and_prints_its_link(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    state_path = tmp_path / "state.json"

    def run(*args: str) -> int:
        return main(["--state", str(state_path), *args])

    init = ["init", "--host", "203.0.113.10", "--target", "www.example.com", "--allow-non-443"]
    assert run(*init) == 0
    assert run("user", "add", "alice") == 0
    assert run("listener", "add", "8080:cdn-xhttp:cdn.example.com") == 0
    capsys.readouterr()
    assert run("link", "alice") == 0
    links = capsys.readouterr().out.split()
    cdn = [link for link in links if "cdn.example.com" in link]
    assert len(cdn) == 1 and "security=tls" in cdn[0] and "type=xhttp" in cdn[0]
    with pytest.raises(SystemExit):  # a CDN listener can never be the primary one
        run("init", *init[1:], "--profile", "cdn-xhttp", "--force")
