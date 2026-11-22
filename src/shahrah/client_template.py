"""Leak-resistant Xray *client* template for Iran (PasarGuard JSON subscription).

PasarGuard merges each user's proxy outbound (tagged ``proxy``) in **front of** the
outbounds of this template, so the first outbound — the default route — is the tunnel.

Iran profile (Chocolate4U ``geosite.dat`` / ``geoip.dat``):

* ``geosite:category-ir`` + ``geoip:ir`` → DIRECT (and localhost DNS for those names).
* Everything else → DoH (``https://``) which is dialled like normal traffic and therefore
  goes through the tunnel; ``disableFallback`` blocks the system resolver.
* ``domainStrategy: IPIfNonMatch`` so geoip rules apply after domain match fails.
* ``queryStrategy: UseIPv4``; IPv6 destinations are blocked (exit has no useful IPv6).

Clients must ship Chocolate4U Iran rules, not Loyalsoldier CN packs::

  https://github.com/Chocolate4U/Iran-v2ray-rules/releases

Honest limits: WebRTC can still leak in *proxy* mode — use TUN/VPN mode.
"""

from __future__ import annotations

import json
from typing import Any

from .xray_config import PRIVATE_NETWORKS

DEFAULT_DOH = ("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query")
WEBRTC_STUN_DOMAINS: tuple[str, ...] = (
    "stun.l.google.com",
    "stun1.l.google.com",
    "stun2.l.google.com",
    "stun3.l.google.com",
    "stun4.l.google.com",
    "stun.cloudflare.com",
)
# Force these through PasarGuard's prepended ``proxy`` outbound (tag added at merge time).
GOOGLE_AI_DOMAINS: tuple[str, ...] = (
    "domain:googleapis.com",
    "domain:googleusercontent.com",
    "domain:gstatic.com",
    "domain:googlevideo.com",
    "domain:gemini.google.com",
    "domain:aistudio.google.com",
    "domain:ai.google.dev",
    "domain:makersuite.google.com",
    "domain:notebooklm.google.com",
    "domain:generativelanguage.googleapis.com",
    "domain:proactivebackend-pa.googleapis.com",
    "domain:alkalimakersuite-pa.clients6.google.com",
    "domain:bard.google.com",
)
_SNIFFING = {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False}


def _google_ai_routing_rule() -> dict[str, Any]:
    return {"type": "field", "domain": list(GOOGLE_AI_DOMAINS), "outboundTag": "proxy"}


def _base_routing_rules() -> list[dict[str, Any]]:
    return [
        {
            "type": "field",
            "domain": ["geosite:category-ads-all", "geosite:malware", "geosite:phishing"],
            "outboundTag": "BLOCK",
        },
        _google_ai_routing_rule(),
        {
            "type": "field",
            "domain": ["geosite:category-ir", "geosite:private"],
            "outboundTag": "DIRECT",
        },
        {
            "type": "field",
            "ip": ["geoip:ir", "geoip:private", *list(PRIVATE_NETWORKS)],
            "outboundTag": "DIRECT",
        },
        {"type": "field", "ip": ["::/0"], "outboundTag": "BLOCK"},
        {
            "type": "field",
            "domain": [f"full:{name}" for name in WEBRTC_STUN_DOMAINS],
            "outboundTag": "BLOCK",
        },
        {
            "type": "field",
            "ip": ["224.0.0.0/4", "255.255.255.255/32"],
            "outboundTag": "BLOCK",
        },
    ]


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
            "servers": [
                {
                    "address": "localhost",
                    "domains": ["geosite:category-ir", "geosite:private"],
                    "expectIPs": ["geoip:ir"],
                },
                *list(dns_servers),
            ],
            "queryStrategy": "UseIPv4",
            "disableFallback": True,
            "disableFallbackIfMatch": True,
            # No dns.tag: DoH is dialled as ordinary https:// and follows the default
            # outbound (PasarGuard's prepended ``proxy``) without naming it here.
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": _base_routing_rules(),
        },
    }


def xray_ios_client_template(
    *,
    socks_port: int = 10808,
    dns_servers: tuple[str, ...] = DEFAULT_DOH,
) -> dict[str, Any]:
    """PasarGuard client template for iOS apps (Streisand, V2Box, QX, etc.).

    Same Iran leak model as :func:`xray_client_template`, but a single SOCKS inbound
  (lighter on mobile). TLS fingerprint for REALITY still comes from each panel host
  (set ``fingerprint: ios`` on hosts assigned to iOS users). Upload as::

    shahrah panel client-template --name IOS --update

    then assign template ``IOS`` per user or sales group in PasarGuard — do not make it
    the global default.
    """
    if not dns_servers:
        raise ValueError("at least one DoH server is required")
    for server in dns_servers:
        if not server.startswith("https://"):
            raise ValueError(
                f"DNS server must be an https:// DoH URL so it is tunnelled, got {server!r}"
            )
    return {
        "log": {"access": "", "error": "", "loglevel": "warning"},
        "policy": {
            "levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}}
        },
        "inbounds": [_local_inbound("socks", "socks", socks_port)],
        "outbounds": [
            {"protocol": "freedom", "tag": "DIRECT"},
            {"protocol": "blackhole", "tag": "BLOCK"},
        ],
        "dns": {
            "servers": [
                {
                    "address": "localhost",
                    "domains": ["geosite:category-ir", "geosite:private"],
                    "expectIPs": ["geoip:ir"],
                },
                *list(dns_servers),
            ],
            "queryStrategy": "UseIPv4",
            "disableFallback": True,
            "disableFallbackIfMatch": True,
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": _base_routing_rules(),
        },
    }


def dumps(template: dict[str, Any]) -> str:
    return json.dumps(template, indent=2) + "\n"
