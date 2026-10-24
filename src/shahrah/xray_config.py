"""Render an Xray server configuration from typed models.

Design choices that matter for stability and for staying unfindable:

* ``access`` log is disabled: the server never records which sites a user visits.
* Private/loopback ranges and BitTorrent are blocked at the server, so users cannot reach the
  VPS' internal network and abuse reports do not get the VPS suspended.
* Outbound resolution is IPv4-only (``UseIPv4``). A VPS without working IPv6 otherwise causes
  half-open "dead" connections when a site publishes AAAA records.
* The optional stats API listens on loopback only and powers per-user usage accounting.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from .models import Profile, ServerSettings, User

PRIVATE_NETWORKS: tuple[str, ...] = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
)

VISION_FLOW = "xtls-rprx-vision"
_API_TAG = "api"
_API_INBOUND_TAG = "api-in"


def _client(user: User, profile: Profile) -> dict[str, Any]:
    client: dict[str, Any] = {"id": user.uuid, "email": user.label}
    if profile is Profile.REALITY_VISION:
        client["flow"] = VISION_FLOW
    return client


def _stream_settings(server: ServerSettings) -> dict[str, Any]:
    reality = server.reality
    stream: dict[str, Any] = {
        "network": "raw" if server.profile is Profile.REALITY_VISION else "xhttp",
        "security": "reality",
        "realitySettings": {
            "show": False,
            "target": f"{reality.target_host}:{reality.target_port}",
            "xver": 0,
            "serverNames": list(reality.server_names),
            "privateKey": reality.private_key,
            "shortIds": list(reality.short_ids),
            "minClientVer": reality.min_client_ver,
        },
    }
    if server.profile is Profile.REALITY_XHTTP:
        stream["xhttpSettings"] = {"path": server.xhttp_path, "mode": server.xhttp_mode}
    return stream


def render_server_config(
    server: ServerSettings,
    users: Sequence[User],
    *,
    log_level: str = "warning",
) -> dict[str, Any]:
    """Return the full Xray server config as a JSON-serialisable dict."""
    labels = [user.label for user in users]
    if len(set(labels)) != len(labels):
        raise ValueError("user labels must be unique (they key the usage statistics)")
    ids = [user.uuid for user in users]
    if len(set(ids)) != len(ids):
        raise ValueError("user uuids must be unique")

    inbounds: list[dict[str, Any]] = [
        {
            "tag": "in-main",
            "listen": server.listen,
            "port": server.port,
            "protocol": "vless",
            "settings": {
                "clients": [_client(user, server.profile) for user in users],
                "decryption": "none",
            },
            "streamSettings": _stream_settings(server),
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": True,
            },
        }
    ]

    rules: list[dict[str, Any]] = []
    config: dict[str, Any] = {
        "log": {"loglevel": log_level, "access": "none"},
        "inbounds": inbounds,
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }

    if server.stats_api_port is not None:
        inbounds.append(
            {
                "tag": _API_INBOUND_TAG,
                "listen": "127.0.0.1",
                "port": server.stats_api_port,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
            }
        )
        config["stats"] = {}
        config["api"] = {"tag": _API_TAG, "services": ["StatsService"]}
        config["policy"] = {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True},
        }
        rules.append({"type": "field", "inboundTag": [_API_INBOUND_TAG], "outboundTag": _API_TAG})

    rules.append({"type": "field", "ip": list(PRIVATE_NETWORKS), "outboundTag": "block"})
    rules.append({"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"})
    return config


def dumps(config: dict[str, Any]) -> str:
    """Serialise a config deterministically (stable diffs, trailing newline)."""
    return json.dumps(config, indent=2, ensure_ascii=False) + "\n"
