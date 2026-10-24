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

from .models import Listener, Profile, ServerSettings, Tuning, User

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


def _sockopt(tuning: Tuning) -> dict[str, Any]:
    return {
        "tcpKeepAliveIdle": tuning.tcp_keepalive_idle_s,
        "tcpKeepAliveInterval": tuning.tcp_keepalive_interval_s,
    }


def _stream_settings(server: ServerSettings, listener: Listener) -> dict[str, Any]:
    if listener.profile is Profile.CDN_XHTTP:
        # TLS is terminated by the CDN / reverse proxy in front; this inbound is plain XHTTP.
        return {
            "network": "xhttp",
            "security": "none",
            "xhttpSettings": {"path": listener.xhttp_path, "mode": listener.xhttp_mode},
            "sockopt": _sockopt(server.tuning),
        }
    reality = server.reality
    stream: dict[str, Any] = {
        "network": "raw" if listener.profile is Profile.REALITY_VISION else "xhttp",
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
    tuning = server.tuning
    stream["sockopt"] = _sockopt(tuning)
    if listener.profile is Profile.REALITY_XHTTP:
        stream["xhttpSettings"] = {"path": listener.xhttp_path, "mode": listener.xhttp_mode}
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
            "tag": "in-main" if index == 0 else f"in-{listener.port}",
            "listen": server.listen,
            "port": listener.port,
            "protocol": "vless",
            "settings": {
                "clients": [_client(user, listener.profile) for user in users],
                "decryption": "none",
            },
            "streamSettings": _stream_settings(server, listener),
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": True,
            },
        }
        for index, listener in enumerate(server.listeners())
    ]
    rules: list[dict[str, Any]] = []
    config: dict[str, Any] = {
        "log": {"loglevel": log_level, "access": "none"},
        "inbounds": inbounds,
        "outbounds": [
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {"domainStrategy": "UseIPv4"},
                "streamSettings": {"sockopt": _sockopt(server.tuning)},
            },
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": rules},
        "dns": {"servers": list(server.tuning.dns_servers), "queryStrategy": "UseIPv4"},
        "policy": {
            "levels": {
                "0": {
                    "handshake": server.tuning.handshake_s,
                    "connIdle": server.tuning.conn_idle_s,
                    "bufferSize": server.tuning.buffer_size_kb,
                }
            }
        },
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
        config["policy"]["levels"]["0"].update({"statsUserUplink": True, "statsUserDownlink": True})
        config["policy"]["system"] = {"statsInboundUplink": True, "statsInboundDownlink": True}
        rules.append({"type": "field", "inboundTag": [_API_INBOUND_TAG], "outboundTag": _API_TAG})

    rules.append({"type": "field", "ip": list(PRIVATE_NETWORKS), "outboundTag": "block"})
    rules.append({"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"})
    return config


def dumps(config: dict[str, Any]) -> str:
    """Serialise a config deterministically (stable diffs, trailing newline)."""
    return json.dumps(config, indent=2, ensure_ascii=False) + "\n"
