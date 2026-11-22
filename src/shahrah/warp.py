"""Cloudflare WARP egress for Google-family destinations (MIT wgcf + WireGuard).

EXIT IPs leased by Iranian orgs (e.g. Webdade on LeaseWeb) are often geolocated as
IR by Google even when the packet lands in NL. Routing google/youtube/... through
WARP makes Play/YouTube see a Cloudflare country instead.
"""

from __future__ import annotations

import configparser
import io
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import ConfigError

# Domains (and suffixes) that must not see the EXIT's Webdade-tagged address.
WARP_DOMAIN_SUFFIXES: tuple[str, ...] = (
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "ggpht.com",
    "youtube.com",
    "youtu.be",
    "ytimg.com",
    "googlevideo.com",
    "google.com.ir",
    "google.co.uk",
    "google.de",
    "android.com",
    "googleadservices.com",
    "gvt1.com",
    "gvt2.com",
    "withgoogle.com",
)

_WG_KEY = re.compile(r"^[A-Za-z0-9+/]{42,44}=$")


@dataclass(frozen=True, slots=True)
class WarpSettings:
    """WireGuard credentials for a Cloudflare WARP account (from wgcf)."""

    private_key: str
    address_v4: str  # e.g. 172.16.0.2/32
    address_v6: str = ""  # optional
    peer_public_key: str = ""
    endpoint: str = "engage.cloudflareclient.com:2408"
    # When True, *all* egress (not only Google) goes through WARP.
    route_all: bool = False
    dns: str = "1.1.1.1"
    interface: str = "warp"

    def __post_init__(self) -> None:
        if not _WG_KEY.match(self.private_key):
            raise ConfigError("warp private_key looks invalid")
        if self.peer_public_key and not _WG_KEY.match(self.peer_public_key):
            raise ConfigError("warp peer_public_key looks invalid")
        if "/" not in self.address_v4:
            raise ConfigError("warp address_v4 must include a prefix length (e.g. 172.16.0.2/32)")

    def to_dict(self) -> dict[str, Any]:
        return {
            "private_key": self.private_key,
            "address_v4": self.address_v4,
            "address_v6": self.address_v6,
            "peer_public_key": self.peer_public_key,
            "endpoint": self.endpoint,
            "route_all": self.route_all,
            "dns": self.dns,
            "interface": self.interface,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WarpSettings:
        return cls(
            private_key=str(data["private_key"]),
            address_v4=str(data["address_v4"]),
            address_v6=str(data.get("address_v6", "")),
            peer_public_key=str(data.get("peer_public_key", "")),
            endpoint=str(data.get("endpoint", "engage.cloudflareclient.com:2408")),
            route_all=bool(data.get("route_all", False)),
            dns=str(data.get("dns", "1.1.1.1")),
            interface=str(data.get("interface", "warp")),
        )


def parse_wgcf_profile(text: str) -> WarpSettings:
    """Parse a wgcf-generated WireGuard profile into :class:`WarpSettings`."""
    parser = configparser.ConfigParser()
    # Preserve case of keys
    parser.optionxform = str  # type: ignore[assignment]
    try:
        parser.read_file(io.StringIO(text))
    except configparser.Error as exc:
        raise ConfigError(f"warp profile is not valid INI: {exc}") from exc
    if "Interface" not in parser or "Peer" not in parser:
        raise ConfigError("warp profile needs [Interface] and [Peer] sections")
    iface = parser["Interface"]
    peer = parser["Peer"]
    addrs = [a.strip() for a in iface.get("Address", "").split(",") if a.strip()]
    v4 = next((a for a in addrs if ":" not in a), "")
    v6 = next((a for a in addrs if ":" in a), "")
    if not v4:
        raise ConfigError("warp profile has no IPv4 Address")
    dns = iface.get("DNS", "1.1.1.1").split(",")[0].strip()
    return WarpSettings(
        private_key=iface["PrivateKey"].strip(),
        address_v4=v4,
        address_v6=v6,
        peer_public_key=peer["PublicKey"].strip(),
        endpoint=peer.get("Endpoint", "engage.cloudflareclient.com:2408").strip(),
        dns=dns or "1.1.1.1",
    )


def load_wgcf_profile(path: Path) -> WarpSettings:
    return parse_wgcf_profile(path.read_text(encoding="utf-8"))


def _engage_ipv4_endpoint(endpoint: str) -> str:
    """Resolve a hostname engage endpoint to an IPv4 ``ip:port`` (no v6 AAAA)."""
    host, _, port = endpoint.rpartition(":")
    if not host or not port:
        return endpoint
    if not any(c.isalpha() for c in host):
        return endpoint  # already literal
    try:
        infos = socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_DGRAM)
    except (socket.gaierror, OSError, ValueError):
        return endpoint
    if not infos:
        return endpoint
    ip = infos[0][4][0]
    return f"{ip}:{port}"


def ipv4_only(settings: WarpSettings) -> WarpSettings:
    """Drop IPv6 WARP address and pin an IPv4 engage endpoint.

    IPv6 WARP exits are often geolocated outside NL (field: RU). Hostname endpoints
    can resolve to AAAA; force an A-record ``ip:port`` so ForceIPv4 stays on CF IPv4.
    """
    from dataclasses import replace

    return replace(
        settings,
        address_v6="",
        endpoint=_engage_ipv4_endpoint(settings.endpoint),
    )


def xray_outbound(settings: WarpSettings) -> dict[str, Any]:
    """Xray WireGuard outbound that dials Cloudflare WARP."""
    addresses = [settings.address_v4]
    if settings.address_v6:
        addresses.append(settings.address_v6)
    peer: dict[str, Any] = {
        "publicKey": settings.peer_public_key,
        "endpoint": settings.endpoint,
        "keepAlive": 25,
    }
    return {
        "tag": "warp",
        "protocol": "wireguard",
        "settings": {
            "secretKey": settings.private_key,
            "address": addresses,
            "peers": [peer],
            "domainStrategy": "ForceIPv4",
        },
    }


def xray_routing_rules(settings: WarpSettings) -> list[dict[str, Any]]:
    """Routing rules that send Google-family (or all) traffic to the WARP outbound."""
    if settings.route_all:
        return [{"type": "field", "network": "tcp,udp", "outboundTag": "warp"}]
    # domain rules: full and domain: suffix form
    domains: list[str] = []
    for suffix in WARP_DOMAIN_SUFFIXES:
        s = suffix.rstrip(".")
        domains.append(f"domain:{s}")
    # unique preserve order
    seen: set[str] = set()
    uniq = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    return [{"type": "field", "domain": uniq, "outboundTag": "warp"}]


def hy2_outbounds(settings: WarpSettings) -> list[str]:
    """YAML lines for Hysteria2 outbounds that bind to the WARP interface."""
    return [
        "outbounds:",
        "  - name: direct",
        "    type: direct",
        "    direct:",
        '      mode: "4"',
        "  - name: warp",
        "    type: direct",
        "    direct:",
        '      mode: "4"',
        f"      bindDevice: {settings.interface}",
    ]


def hy2_acl_lines(settings: WarpSettings) -> list[str]:
    """Google-family ACL lines (prepended before private rejects).

    ``route_all`` is empty here; use :func:`hy2_acl_route_all` after rejects.
    """
    if settings.route_all:
        return []
    lines = []
    for suffix in WARP_DOMAIN_SUFFIXES:
        s = suffix.rstrip(".")
        lines.append(f"    - warp(suffix:{s})")
    return lines


def hy2_acl_route_all(settings: WarpSettings) -> list[str]:
    """Final ``warp(all)`` catch-all; append *after* private-network rejects."""
    if settings.route_all:
        return ["    - warp(all)"]
    return []


def wg_quick_conf(settings: WarpSettings) -> str:
    """Render a wg-quick profile for Hy2 ``bindDevice`` only.

    Safe defaults (never steal the host default route or DNS):
    * ``Table = off`` — no policy routing / main-table changes
    * no ``DNS =`` line — leave systemd-resolved alone
    * ``MTU = 1280`` — fits under EXIT eth0 MTU 1400 with WG overhead
    * ``AllowedIPs = 0.0.0.0/0`` is fine with Table=off (no routes installed)
    """
    addrs = settings.address_v4
    if settings.address_v6:
        addrs = f"{settings.address_v4}, {settings.address_v6}"
    return (
        "[Interface]\n"
        f"PrivateKey = {settings.private_key}\n"
        f"Address = {addrs}\n"
        "MTU = 1280\n"
        "Table = off\n"
        "\n[Peer]\n"
        f"PublicKey = {settings.peer_public_key}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"Endpoint = {settings.endpoint}\n"
        "PersistentKeepalive = 25\n"
    )
