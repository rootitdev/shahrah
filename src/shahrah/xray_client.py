"""Render an Xray *client* config used by the tunnel prober.

One long-lived Xray process serves every endpoint: each endpoint gets its own SOCKS inbound on
loopback, wired to its own outbound. A probe is then just a SOCKS request on that port, so a
cycle costs a few sockets instead of spawning one Xray per endpoint per cycle.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .models import Endpoint, Profile, User
from .xray_config import VISION_FLOW

LOOPBACK = "127.0.0.1"


def inbound_tag(index: int) -> str:
    return f"probe-in-{index}"


def outbound_tag(index: int) -> str:
    return f"probe-out-{index}"


def _outbound(endpoint: Endpoint, user: User, index: int) -> dict[str, Any]:
    vless_user: dict[str, Any] = {"id": user.uuid, "encryption": "none"}
    stream: dict[str, Any] = {
        "security": "reality",
        "realitySettings": {
            "serverName": endpoint.sni,
            "fingerprint": endpoint.fingerprint,
            "publicKey": endpoint.public_key,
            "shortId": endpoint.short_id,
            "spiderX": "",
        },
    }
    if endpoint.profile is Profile.REALITY_VISION:
        vless_user["flow"] = VISION_FLOW
        stream["network"] = "raw"
    else:
        stream["network"] = "xhttp"
        stream["xhttpSettings"] = {"path": endpoint.xhttp_path, "mode": endpoint.xhttp_mode}
    return {
        "tag": outbound_tag(index),
        "protocol": "vless",
        "settings": {
            "vnext": [{"address": endpoint.host, "port": endpoint.port, "users": [vless_user]}]
        },
        "streamSettings": stream,
    }


def render_probe_config(
    endpoints: Sequence[Endpoint],
    user: User,
    ports: Sequence[int],
    *,
    log_level: str = "warning",
) -> dict[str, Any]:
    """Return a client config exposing ``endpoints[i]`` as SOCKS on ``127.0.0.1:ports[i]``."""
    if len(endpoints) != len(ports):
        raise ValueError("need exactly one local port per endpoint")
    if len(set(ports)) != len(ports):
        raise ValueError("local probe ports must be unique")
    if not endpoints:
        raise ValueError("at least one endpoint is required")
    return {
        "log": {"loglevel": log_level},
        "inbounds": [
            {
                "tag": inbound_tag(i),
                "listen": LOOPBACK,
                "port": port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
            for i, port in enumerate(ports)
        ],
        "outbounds": [_outbound(endpoint, user, i) for i, endpoint in enumerate(endpoints)],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": [inbound_tag(i)],
                    "outboundTag": outbound_tag(i),
                }
                for i in range(len(endpoints))
            ],
        },
    }
