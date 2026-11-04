"""paqet: raw-packet KCP crisis path (external, pinned binary).

`paqet <https://github.com/hanselime/paqet>`_ (MIT licence, Go, alpha) crafts TCP packets
itself and captures replies with pcap, carrying KCP+smux (encrypted, multiplexed) on top.
Because it does not use the kernel TCP stack there is no SYN handshake for middleboxes to key
on; net4people/bbs#570 reports it staying usable Iran -> Hetzner during the January 2026
shutdown, while BGP-level withdrawal still kills it. Constraints taken from upstream docs:

* both ends need root (raw sockets); on a phone that means root, so the realistic topology
  is *Iran-hosted relay (paqet client) -> foreign exit (paqet server)*, not end users;
* the server port must not be 80/443 (its iptables rules would also hit outbound traffic);
* the server needs NOTRACK + RST-drop rules or the kernel resets the flows;
* carrier-grade NAT on the client side often breaks it.

Shahrah never vendors paqet code: it renders configs, emits the firewall rules, pins the
release checksum, and starts/stops the client unit when the Oracle reports a crisis.
"""

from __future__ import annotations

import ipaddress
import json
import re
import secrets
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from .models import ConfigError
from .oracle import Mode

PAQET_VERSION = "v1.0.0-alpha.21"
# sha256 of the release tarballs, from the GitHub release asset digests (published
# 2026-08-22); the amd64 one was re-verified by downloading the asset.
PAQET_SHA256 = {
    "linux-amd64": "4f2f69e0493746726598485ef18df43372470a1514f8021594137e522f0f4fc7",
    "linux-arm64": "be5c7b35a0a93832063e1dc7fddeb76d4597fb9de76abdfdf7b8574b775e3885",
}
FORBIDDEN_PORTS = frozenset({80, 443})
KCP_MODES = frozenset({"normal", "fast", "fast2", "fast3"})
CLIENT_UNIT = "shahrah-paqet-client"
_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
CRISIS_MODES = frozenset({Mode.RESTRICTED, Mode.OUTAGE})


def generate_key() -> str:
    return secrets.token_urlsafe(32)


def _check_common(interface: str, mac: str, key: str, kcp_mode: str) -> None:
    if not _IFACE_RE.match(interface):
        raise ConfigError(f"invalid network interface name: {interface!r}")
    if not _MAC_RE.match(mac.lower()):
        raise ConfigError(f"router_mac must look like aa:bb:cc:dd:ee:ff: {mac!r}")
    if len(key) < 16 or any(ch in key for ch in '"\\\n'):
        raise ConfigError("paqet key must be >= 16 chars without quotes/newlines")
    if kcp_mode not in KCP_MODES:
        raise ConfigError(f"kcp mode must be one of {sorted(KCP_MODES)}")


def _check_ipv4(value: str, what: str) -> None:
    try:
        ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ConfigError(f"{what} must be an IPv4 address: {value!r}") from exc


def _check_port(port: int) -> None:
    if not 1024 < port < 65536 or port in FORBIDDEN_PORTS:
        raise ConfigError("paqet port must be a non-standard port above 1024 (upstream rule)")


@dataclass(frozen=True, slots=True)
class PaqetServer:
    interface: str
    ipv4: str  # the server's own address on ``interface``
    router_mac: str
    key: str
    port: int = 9999
    kcp_mode: str = "fast"
    conn: int = 1

    def __post_init__(self) -> None:
        _check_common(self.interface, self.router_mac, self.key, self.kcp_mode)
        _check_ipv4(self.ipv4, "server ipv4")
        _check_port(self.port)
        if not 1 <= self.conn <= 256:
            raise ConfigError("conn must be 1..256")


@dataclass(frozen=True, slots=True)
class PaqetClient:
    interface: str
    local_ipv4: str
    router_mac: str
    server_ipv4: str
    key: str
    server_port: int = 9999
    socks_listen: str = "127.0.0.1:1080"
    kcp_mode: str = "fast"
    conn: int = 1

    def __post_init__(self) -> None:
        _check_common(self.interface, self.router_mac, self.key, self.kcp_mode)
        _check_ipv4(self.local_ipv4, "local ipv4")
        _check_ipv4(self.server_ipv4, "server ipv4")
        _check_port(self.server_port)
        host, _, port = self.socks_listen.rpartition(":")
        if host not in {"127.0.0.1", "localhost"} or not port.isdigit():
            raise ConfigError("socks_listen must be loopback host:port (never expose SOCKS)")
        if not 1 <= self.conn <= 256:
            raise ConfigError("conn must be 1..256")

    @property
    def socks_port(self) -> int:
        return int(self.socks_listen.rpartition(":")[2])


def _q(value: str) -> str:
    return json.dumps(value)  # a JSON string is a valid YAML scalar


def _transport(key: str, mode: str, conn: int) -> list[str]:
    return [
        "transport:",
        '  protocol: "kcp"',
        f"  conn: {conn}",
        "  kcp:",
        f"    mode: {_q(mode)}",
        '    block: "aes"',
        f"    key: {_q(key)}",
    ]


def render_server(cfg: PaqetServer) -> str:
    lines = [
        "# rendered by shahrah; secret - keep mode 0600",
        'role: "server"',
        "log:",
        '  level: "warn"',
        "listen:",
        f'  addr: ":{cfg.port}"',
        "network:",
        f"  interface: {_q(cfg.interface)}",
        "  ipv4:",
        f"    addr: {_q(f'{cfg.ipv4}:{cfg.port}')}",
        f"    router_mac: {_q(cfg.router_mac.lower())}",
        *_transport(cfg.key, cfg.kcp_mode, cfg.conn),
    ]
    return "\n".join(lines) + "\n"


def render_client(cfg: PaqetClient) -> str:
    lines = [
        "# rendered by shahrah; secret - keep mode 0600",
        'role: "client"',
        "log:",
        '  level: "warn"',
        "socks5:",
        f"  - listen: {_q(cfg.socks_listen)}",
        "network:",
        f"  interface: {_q(cfg.interface)}",
        "  ipv4:",
        f"    addr: {_q(f'{cfg.local_ipv4}:0')}",
        f"    router_mac: {_q(cfg.router_mac.lower())}",
        "server:",
        f"  addr: {_q(f'{cfg.server_ipv4}:{cfg.server_port}')}",
        *_transport(cfg.key, cfg.kcp_mode, cfg.conn),
    ]
    return "\n".join(lines) + "\n"


def server_firewall_rules(port: int) -> list[list[str]]:
    """iptables commands from the upstream README (NOTRACK + drop kernel RSTs + accept)."""
    _check_port(port)
    p = str(port)
    return [
        ["iptables", "-t", "raw", "-A", "PREROUTING", "-p", "tcp", "--dport", p, "-j", "NOTRACK"],
        ["iptables", "-t", "raw", "-A", "OUTPUT", "-p", "tcp", "--sport", p, "-j", "NOTRACK"],
        [
            "iptables",
            "-t",
            "mangle",
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "--sport",
            p,
            "--tcp-flags",
            "RST",
            "RST",
            "-j",
            "DROP",
        ],
        ["iptables", "-t", "filter", "-A", "INPUT", "-p", "tcp", "--dport", p, "-j", "ACCEPT"],
        ["iptables", "-t", "filter", "-A", "OUTPUT", "-p", "tcp", "--sport", p, "-j", "ACCEPT"],
    ]


def systemd_unit(role: str, config_path: str, binary: str = "/usr/local/bin/paqet") -> str:
    if role not in {"server", "client"}:
        raise ConfigError("role must be server or client")
    return (
        "[Unit]\n"
        f"Description=shahrah paqet {role} (raw-packet crisis path)\n"
        "After=network-online.target\nWants=network-online.target\n\n"
        "[Service]\n"
        f"ExecStart={binary} run -c {config_path}\n"
        "Restart=always\nRestartSec=3\n"
        "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN\n"
        "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN\n"
        "NoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


Runner = Callable[[Sequence[str]], object]


def _systemctl(argv: Sequence[str]) -> object:
    return subprocess.run(list(argv), check=True, capture_output=True, timeout=30)  # noqa: S603


def crisis_hook(
    unit: str = CLIENT_UNIT, runner: Runner = _systemctl
) -> Callable[[Mode, Mode], None]:
    """Brain ``on_mode_change`` hook: start the paqet client in a crisis, stop it after."""

    def hook(previous: Mode, current: Mode) -> None:
        entering = current in CRISIS_MODES and previous not in CRISIS_MODES
        leaving = previous in CRISIS_MODES and current not in CRISIS_MODES
        if entering:
            runner(["systemctl", "start", unit])
        elif leaving:
            runner(["systemctl", "stop", unit])

    return hook
