"""Leak-resistant Xray *client* template for the panel's JSON subscription.

PasarGuard merges each user's proxy outbound (tagged ``proxy``) in **front of** the outbounds
of this template, so the first outbound - the default route - is always the tunnel. The template
makes the rest of the client config leak-resistant:

* DNS is resolved by DoH servers addressed as ordinary ``https://`` URLs, so the queries are
  routed (and therefore tunnelled) like any other traffic, never through the local resolver.
  ``disableFallback`` stops Xray from silently falling back to the system resolver, which is
  the classic DNS leak. Only A records are requested (``UseIPv4``).
* ``domainStrategy: AsIs`` - destinations are never resolved on the device to evaluate rules;
  the server resolves them.
* All IPv6 is blocked inside the client: the exit has no IPv6, so allowing it can only leak.
* Local proxy ports listen on loopback, never on the network.

Honest limits (documented, not hidden): a browser's WebRTC bypasses a SOCKS/HTTP proxy and can
reveal the real address in *proxy mode*. Use a client's TUN/VPN mode or disable WebRTC in the
browser; a dedicated client with a kill-switch is a later project phase.
"""

from __future__ import annotations

import json
from typing import Any

from .xray_config import PRIVATE_NETWORKS

DEFAULT_DOH = ("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query")
# Common browser WebRTC STUN hosts. Blocking them in *proxy* mode reduces IP leaks;
# TUN/VPN mode or a dedicated kill-switch client is still required for full coverage.
WEBRTC_STUN_DOMAINS: tuple[str, ...] = (
    "stun.l.google.com",
    "stun1.l.google.com",
    "stun2.l.google.com",
    "stun3.l.google.com",
    "stun4.l.google.com",
    "stun.cloudflare.com",
)
_SNIFFING = {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False}


def _local_inbound(tag: str, protocol: str, port: int) -> dict[str, Any]:
    return {
        "tag": tag,
        "port": port,
        "listen": "127.0.0.1",
        "protocol": protocol,
        "sniffing": dict(_SNIFFING),
        "settings": {"auth": "noauth", "udp": True, "allowTransparent": False},
    }


def xray_client_template(
    *,
    socks_port: int = 10808,
    http_port: int = 10809,
    dns_servers: tuple[str, ...] = DEFAULT_DOH,
) -> dict[str, Any]:
    if not dns_servers:
        raise ValueError("at least one DoH server is required")
    for server in dns_servers:
        if not server.startswith("https://"):
            raise ValueError(
                f"DNS server must be an https:// DoH URL so it is tunnelled, got {server!r}"
            )
    if socks_port == http_port:
        raise ValueError("socks and http ports must differ")
    return {
        "log": {"access": "", "error": "", "loglevel": "warning"},
        "policy": {
            "levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}}
        },
        "inbounds": [
            _local_inbound("socks", "socks", socks_port),
            _local_inbound("http", "http", http_port),
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "DIRECT"},
            {"protocol": "blackhole", "tag": "BLOCK"},
        ],
        "dns": {
            "servers": list(dns_servers),
            "queryStrategy": "UseIPv4",
            "disableFallback": True,
            "disableFallbackIfMatch": True,
        },
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                # LAN stays local (printers, router UI); evaluated before the IPv6 block.
                {"type": "field", "ip": list(PRIVATE_NETWORKS), "outboundTag": "DIRECT"},
                {"type": "field", "ip": ["::/0"], "outboundTag": "BLOCK"},
                {
                    "type": "field",
                    "domain": [f"full:{name}" for name in WEBRTC_STUN_DOMAINS],
                    "outboundTag": "BLOCK",
                },
                # Multicast / broadcast must never leave the device via the tunnel.
                {
                    "type": "field",
                    "ip": ["224.0.0.0/4", "255.255.255.255/32"],
                    "outboundTag": "BLOCK",
                },
            ],
        },
    }


def dumps(template: dict[str, Any]) -> str:
    return json.dumps(template, indent=2) + "\n"
