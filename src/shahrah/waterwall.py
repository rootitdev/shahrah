"""WaterWall backhaul for the Iran -> exit leg (external, pinned binary).

`WaterWall <https://github.com/radkesvat/WaterWall>`_ (MPL-2.0, C) composes tunnels from
small nodes chained by ``next``. Shahrah only renders the JSON (node names and settings come
from the upstream node reference docs); no WaterWall source is copied.

Topology. Users dial the Iran server with their normal REALITY link; WaterWall on the Iran
server does *not* decrypt anything, it carries the raw TCP stream to the exit's Xray. The
Iran box therefore holds no user keys and no panel (bbs#675: a panel on the Iran side is a
liability). The leg between the two servers is wrapped in WaterWall's own ``Reality`` pair, so
on the wire it is a TLS 1.3 session to ``cover_sni``; anyone other than the peer who connects
is forwarded to the real cover site.

Modes:

* ``reverse`` (default) - the exit dials *into* Iran and keeps ``pool`` idle connections
  ready (ReverseClient/ReverseServer). The exit exposes no port, so it cannot be found by
  scanning, and a user's new connection skips the Iran->exit TCP+TLS handshake (one
  international RTT saved per Instagram request burst).
* ``direct`` - Iran dials the exit (simpler; use when Iran inbound from abroad is filtered).

``cover_sni`` is dialled by the RealityServer side (Iran in reverse mode) on every leg
handshake, so it must be fast from that network; a slow cover makes direct mode time out.

The tunnel listener only accepts the peer's address (``whitelist``): the ops logs showed the
backhaul port being found and hammered when left open to everyone (docs/DIAG_LESSONS.md).
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any

from .models import ConfigError, is_ip, validate_host, validate_port

WATERWALL_VERSION = "v1.5.2"
# sha256 of the release zips, from the GitHub release asset digests (published 2026-10-26);
# linux-gcc-x64 was re-verified by downloading the asset.
WATERWALL_SHA256 = {
    "linux-gcc-x64": "1d9ba7da4a3ab42b5685e5ecf03cf3d93a97ede5fd9fce8a12dbfc23e04a829a",
    "linux-gcc-x64-old-cpu": "bdd20c083c15bc00df197b2f0562aeba013663230caefc95ca56292b839992b0",
    "linux-gcc-arm64": "56486a3a8d02a67f782d45a6155bea4e437348c72611a3f685459d97966ff96b",
    "linux-gcc-arm64-old-cpu": "bd553fb76bdc37769854a46e689ca3796b9d2c6258170daaa9d4ef84031a9347",
}
MODES = frozenset({"reverse", "direct"})
UNIT = "shahrah-waterwall"


@dataclass(frozen=True, slots=True)
class Backhaul:
    iran_ip: str
    exit_ip: str
    password: str  # WaterWall Reality secret: 1..32 bytes
    cover_sni: str = "www.speedtest.net"
    mode: str = "reverse"
    user_ports: tuple[int, ...] = (443,)  # Iran ports users dial
    tunnel_port: int = 8443  # inter-server leg
    exit_service: str = "127.0.0.1:443"  # Xray on the exit, as seen from the exit
    pool: int = 8  # reverse mode: idle pre-opened connections per worker
    workers: int = 0  # 0 = one per CPU
    listen: str = "0.0.0.0"  # noqa: S104 - public listener by design
    restrict_peer: bool = True

    def __post_init__(self) -> None:
        for value, what in ((self.iran_ip, "iran_ip"), (self.exit_ip, "exit_ip")):
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise ConfigError(f"{what} must be an IP address: {value!r}") from exc
        if not 16 <= len(self.password.encode()) <= 32 or any(c in self.password for c in '"\\'):
            raise ConfigError("backhaul password must be 16..32 bytes (WaterWall Reality limit)")
        validate_host(self.cover_sni, "cover sni")
        if is_ip(self.cover_sni):
            raise ConfigError("cover_sni must be a domain name")
        if self.mode not in MODES:
            raise ConfigError(f"mode must be one of {sorted(MODES)}")
        if not self.user_ports:
            raise ConfigError("at least one user port is required")
        for port in (*self.user_ports, self.tunnel_port):
            validate_port(port)
        if self.tunnel_port in self.user_ports:
            raise ConfigError("tunnel_port must differ from the user ports")
        host, _, port = self.exit_service.rpartition(":")
        if not host or not port.isdigit():
            raise ConfigError("exit_service must be host:port")
        validate_port(int(port), "exit service port")
        if not 1 <= self.pool <= 256:
            raise ConfigError("pool must be 1..256")
        if not 0 <= self.workers <= 64:
            raise ConfigError("workers must be 0..64")

    @property
    def _service(self) -> tuple[str, int]:
        host, _, port = self.exit_service.rpartition(":")
        return host, int(port)


def _node(name: str, type_: str, settings: dict[str, Any], nxt: str | None = None) -> dict:
    node: dict[str, Any] = {"name": name, "type": type_, "settings": settings}
    if nxt:
        node["next"] = nxt
    return node


def _peer_cidr(ip: str) -> str:
    return f"{ip}/{32 if ipaddress.ip_address(ip).version == 4 else 128}"


def _listener(b: Backhaul, name: str, port: int | list[int], nxt: str, peer: str | None) -> dict:
    settings: dict[str, Any] = {"address": b.listen, "port": port, "nodelay": True}
    if peer and b.restrict_peer:
        settings["whitelist"] = [_peer_cidr(peer)]
    return _node(name, "TcpListener", settings, nxt)


def _connector(name: str, host: str, port: int) -> dict:
    return _node(
        name,
        "TcpConnector",
        {"address": host, "port": port, "nodelay": True, "domain-strategy": "prefer-ipv4"},
    )


def _reality(b: Backhaul, side: str, nxt: str) -> dict:
    if side == "client":
        settings: dict[str, Any] = {"sni": b.cover_sni, "verify": True, "password": b.password}
        return _node("bh-reality-client", "RealityClient", settings, nxt)
    settings = {"destination": "bh-cover", "password": b.password}
    return _node("bh-reality-server", "RealityServer", settings, nxt)


def _ports(b: Backhaul) -> int | list[int]:
    return b.user_ports[0] if len(b.user_ports) == 1 else list(b.user_ports)


def render_iran(b: Backhaul) -> dict[str, Any]:
    """Chain for the Iran server."""
    cover = _connector("bh-cover", b.cover_sni, 443)
    if b.mode == "direct":
        nodes = [
            _listener(b, "users", _ports(b), "bh-reality-client", None),
            _reality(b, "client", "to-exit"),
            _connector("to-exit", b.exit_ip, b.tunnel_port),
        ]
    else:
        nodes = [
            _listener(b, "users", _ports(b), "users-bridge", None),
            _node("users-bridge", "Bridge", {"pair": "rev-bridge"}),
            _listener(b, "from-exit", b.tunnel_port, "bh-reality-server", b.exit_ip),
            _reality(b, "server", "rev-server"),
            _node("rev-server", "ReverseServer", {}, "rev-bridge"),
            _node("rev-bridge", "Bridge", {"pair": "users-bridge"}),
            cover,
        ]
    return {"name": "shahrah-backhaul-iran", "nodes": nodes}


def render_exit(b: Backhaul) -> dict[str, Any]:
    """Chain for the foreign exit server."""
    host, port = b._service
    if b.mode == "direct":
        nodes = [
            _listener(b, "from-iran", b.tunnel_port, "bh-reality-server", b.iran_ip),
            _reality(b, "server", "service"),
            _connector("service", host, port),
            _connector("bh-cover", b.cover_sni, 443),
        ]
    else:
        nodes = [
            _node("svc-bridge", "Bridge", {"pair": "rev-bridge"}, "service"),
            _connector("service", host, port),
            _node("rev-bridge", "Bridge", {"pair": "svc-bridge"}, "rev-client"),
            _node("rev-client", "ReverseClient", {"minimum-unused": b.pool}, "bh-reality-client"),
            _reality(b, "client", "to-iran"),
            _connector("to-iran", b.iran_ip, b.tunnel_port),
        ]
    return {"name": "shahrah-backhaul-exit", "nodes": nodes}


def core_json(config_file: str, workers: int = 0, log_dir: str = "/var/log/shahrah-ww/") -> dict:
    """``core.json``: logs warn-level only (no per-connection history on a seized box)."""
    level = {"loglevel": "WARN", "file": "", "console": True}
    misc: dict[str, Any] = {"ram-profile": "server", "mtu": 1500, "try-enabling-bbr": True}
    if workers:
        misc["workers"] = workers
    return {
        "log": {
            "path": log_dir,
            "internal": dict(level, file="internal.log"),
            "core": dict(level, file="core.log"),
            "network": dict(level, file="network.log"),
            "dns": dict(level, file="dns.log"),
        },
        "configs": [config_file],
        "misc": misc,
    }


def dumps(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2) + "\n"


def systemd_unit(
    workdir: str = "/etc/shahrah/waterwall", binary: str = "/usr/local/bin/waterwall"
) -> str:
    return (
        "[Unit]\n"
        "Description=shahrah WaterWall backhaul (Iran <-> exit leg)\n"
        "After=network-online.target\nWants=network-online.target\n\n"
        "[Service]\n"
        f"WorkingDirectory={workdir}\n"
        f"ExecStart={binary} -c:{workdir}/core.json\n"
        "Restart=always\nRestartSec=3\n"
        "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
        "NoNewPrivileges=true\nLimitNOFILE=1048576\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
