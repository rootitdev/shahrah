from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from shahrah.models import (
    ConfigError,
    Listener,
    Profile,
    RealityServer,
    ServerSettings,
    Tuning,
    User,
)
from shahrah.xray_config import PRIVATE_NETWORKS, VISION_FLOW, dumps, render_server_config


def test_vision_profile_shape(server: ServerSettings, users: list[User]) -> None:
    config = render_server_config(server, users)
    inbound = config["inbounds"][0]
    assert inbound["port"] == 443
    assert inbound["streamSettings"]["network"] == "raw"
    assert inbound["streamSettings"]["security"] == "reality"
    assert all(c["flow"] == VISION_FLOW for c in inbound["settings"]["clients"])
    reality = inbound["streamSettings"]["realitySettings"]
    assert reality["target"] == "www.example.com:443"
    assert reality["serverNames"] == ["www.example.com"]
    assert "xhttpSettings" not in inbound["streamSettings"]


def test_xhttp_profile_has_no_flow(reality: RealityServer, users: list[User]) -> None:
    server = ServerSettings(
        profile=Profile.REALITY_XHTTP, reality=reality, xhttp_path="/p", xhttp_mode="stream-one"
    )
    stream = render_server_config(server, users)["inbounds"][0]["streamSettings"]
    assert stream["network"] == "xhttp"
    assert stream["xhttpSettings"] == {"path": "/p", "mode": "stream-one"}
    clients = render_server_config(server, users)["inbounds"][0]["settings"]["clients"]
    assert all("flow" not in client for client in clients)


def test_privacy_and_abuse_defaults(server: ServerSettings, users: list[User]) -> None:
    config = render_server_config(server, users)
    assert config["log"]["access"] == "none"
    rules = config["routing"]["rules"]
    block_ip = next(rule for rule in rules if "ip" in rule)
    assert block_ip["outboundTag"] == "block"
    assert set(PRIVATE_NETWORKS) == set(block_ip["ip"])
    assert any(rule.get("protocol") == ["bittorrent"] for rule in rules)
    direct = next(o for o in config["outbounds"] if o["tag"] == "direct")
    assert direct["settings"]["domainStrategy"] == "UseIPv4"


def test_stats_api_is_loopback_only_and_routed_first(
    server: ServerSettings, users: list[User]
) -> None:
    config = render_server_config(server, users)
    api_in = next(i for i in config["inbounds"] if i["tag"] == "api-in")
    assert api_in["listen"] == "127.0.0.1"
    assert config["routing"]["rules"][0]["inboundTag"] == ["api-in"]


def test_stats_api_is_optional(server: ServerSettings, users: list[User]) -> None:
    config = render_server_config(replace(server, stats_api_port=None), users)
    assert len(config["inbounds"]) == 1
    assert "api" not in config


def test_duplicate_users_are_rejected(server: ServerSettings, users: list[User]) -> None:
    with pytest.raises(ValueError, match="labels"):
        render_server_config(server, [users[0], User(users[1].uuid, users[0].label)])
    with pytest.raises(ValueError, match="uuids"):
        render_server_config(server, [users[0], User(users[0].uuid, "other")])


def test_output_is_deterministic_json(server: ServerSettings, users: list[User]) -> None:
    text = dumps(render_server_config(server, users))
    assert text.endswith("\n")
    assert text == dumps(render_server_config(server, users))
    json.loads(text)


@pytest.mark.parametrize("profile", list(Profile))
@pytest.mark.parametrize("with_stats", [True, False])
def test_real_xray_accepts_generated_config(
    profile: Profile,
    with_stats: bool,
    users: list[User],
    xray_bin: str,
    real_private_key: str,
    tmp_path: Path,
) -> None:
    reality = RealityServer(
        target_host="www.example.com", private_key=real_private_key, short_ids=("ab12",)
    )
    server = ServerSettings(
        profile=profile, reality=reality, stats_api_port=10085 if with_stats else None
    )
    path = tmp_path / "config.json"
    path.write_text(dumps(render_server_config(server, users)), encoding="utf-8")
    result = subprocess.run(
        [xray_bin, "run", "-test", "-c", str(path)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Configuration OK" in result.stdout + result.stderr


def test_stability_tuning_is_explicit_in_the_config(
    server: ServerSettings, users: list[User]
) -> None:
    config = render_server_config(server, users)
    level = config["policy"]["levels"]["0"]
    assert level["connIdle"] == 300
    assert level["handshake"] == 4
    assert level["bufferSize"] == 128  # bounded memory per connection
    # stats flags are merged in without dropping the tuning
    assert level["statsUserUplink"] is True
    # keepalive on both sides: client-facing socket and the upstream connections
    inbound_sockopt = config["inbounds"][0]["streamSettings"]["sockopt"]
    freedom_sockopt = config["outbounds"][0]["streamSettings"]["sockopt"]
    assert (
        inbound_sockopt == freedom_sockopt == {"tcpKeepAliveIdle": 30, "tcpKeepAliveInterval": 15}
    )


def test_server_resolves_names_itself_over_doh_ipv4_only(
    server: ServerSettings, users: list[User]
) -> None:
    dns = render_server_config(server, users)["dns"]
    assert dns["queryStrategy"] == "UseIPv4"
    assert all(s.startswith("https+local://") for s in dns["servers"])


def test_tuning_overrides_flow_into_the_config(server: ServerSettings, users: list[User]) -> None:
    tuned = replace(
        server, tuning=Tuning(dns_servers=("localhost",), conn_idle_s=120, buffer_size_kb=64)
    )
    config = render_server_config(tuned, users)
    assert config["dns"]["servers"] == ["localhost"]
    assert config["policy"]["levels"]["0"]["connIdle"] == 120
    assert config["policy"]["levels"]["0"]["bufferSize"] == 64


@pytest.mark.parametrize(
    "kwargs",
    [
        {"dns_servers": ()},
        {"dns_servers": ("bad entry",)},
        {"conn_idle_s": 5},
        {"buffer_size_kb": 0},
        {"buffer_size_kb": 10**6},
        {"tcp_keepalive_interval_s": True},
    ],
)
def test_invalid_tuning_is_rejected(kwargs: dict[str, object]) -> None:
    with pytest.raises(ConfigError):
        Tuning(**kwargs)  # type: ignore[arg-type]


def test_every_listener_gets_its_own_inbound_with_the_right_transport(
    reality: RealityServer, users: list[User]
) -> None:
    server = ServerSettings(
        profile=Profile.REALITY_VISION,
        reality=reality,
        extra_listeners=(Listener(80, Profile.REALITY_XHTTP), Listener(53, Profile.REALITY_XHTTP)),
    )
    inbounds = render_server_config(server, users)["inbounds"]
    assert [(i["tag"], i["port"]) for i in inbounds] == [
        ("in-main", 443),
        ("in-80", 80),
        ("in-53", 53),
    ]
    networks = [i["streamSettings"]["network"] for i in inbounds]
    assert networks == ["raw", "xhttp", "xhttp"]
    flows = [i["settings"]["clients"][0].get("flow") for i in inbounds]
    assert flows == ["xtls-rprx-vision", None, None]  # only Vision carries a flow
    keys = {i["streamSettings"]["realitySettings"]["privateKey"] for i in inbounds}
    assert len(keys) == 1  # one REALITY identity for all ports


def test_real_xray_accepts_443_80_and_53_together(
    reality: RealityServer, users: list[User], xray_bin: str, real_private_key: str, tmp_path: Path
) -> None:
    server = ServerSettings(
        profile=Profile.REALITY_VISION,
        reality=replace(reality, private_key=real_private_key),
        extra_listeners=(Listener(80, Profile.REALITY_XHTTP), Listener(53, Profile.REALITY_XHTTP)),
    )
    path = tmp_path / "multi.json"
    path.write_text(dumps(render_server_config(server, users)), encoding="utf-8")
    result = subprocess.run(
        [xray_bin, "run", "-test", "-c", str(path)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
