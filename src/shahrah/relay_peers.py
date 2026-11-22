"""Named Iran relay peers — one WaterWall backhaul per foreign exit.

Each peer listens on its own ``user_port`` on Iran; clients use separate links/subscription
entries from the respective exit (distinct REALITY keys/users). PasarGuard does not sync
identities across exits automatically.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from . import waterwall as ww
from .models import ConfigError, validate_port


@dataclass(slots=True)
class RelayPeer:
    name: str
    exit_ip: str
    user_port: int = 443
    tunnel_port: int = 8443
    mode: str = "reverse"
    cover_sni: str = "www.speedtest.net"
    cover_addr: str = ""
    iran_ip: str = ""  # filled at apply time on Iran host

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.name.replace("-", "").isalnum():
            raise ConfigError("peer name must be alphanumeric (hyphens allowed)")
        checks: tuple[tuple[str, str], ...] = (("exit", self.exit_ip),)
        if self.iran_ip:
            checks += (("iran", self.iran_ip),)
        for label, addr in checks:
            try:
                ipaddress.ip_address(addr)
            except ValueError as exc:
                raise ConfigError(f"{label}_ip must be valid: {addr!r}") from exc
        if self.mode not in ww.MODES:
            raise ConfigError(f"mode must be one of {sorted(ww.MODES)}")
        for port in (self.user_port, self.tunnel_port):
            validate_port(port)
        if self.user_port == self.tunnel_port:
            raise ConfigError("user_port and tunnel_port must differ")


@dataclass(slots=True)
class RelayPeerStore:
    version: int = 1
    iran_entry_host: str = ""  # clients dial this (Iran public); per-peer user_port selects exit
    peers: tuple[RelayPeer, ...] = ()

    def validate(self) -> None:
        names: set[str] = set()
        user_ports: set[int] = set()
        tunnels: set[int] = set()
        for p in self.peers:
            if p.name in names:
                raise ConfigError(f"duplicate peer name: {p.name!r}")
            names.add(p.name)
            if p.user_port in user_ports:
                raise ConfigError(f"duplicate user_port {p.user_port} for peer {p.name!r}")
            user_ports.add(p.user_port)
            if p.tunnel_port in tunnels:
                raise ConfigError(f"duplicate tunnel_port {p.tunnel_port} for peer {p.name!r}")
            tunnels.add(p.tunnel_port)

    def to_json(self) -> str:
        data = {
            "version": self.version,
            "iran_entry_host": self.iran_entry_host,
            "peers": [asdict(p) for p in self.peers],
        }
        return json.dumps(data, indent=2) + "\n"

    @classmethod
    def from_json(cls, text: str) -> RelayPeerStore:
        data: dict[str, Any] = json.loads(text)
        peers = tuple(RelayPeer(**item) for item in data.get("peers", []))
        store = cls(
            version=int(data.get("version", 1)),
            iran_entry_host=str(data.get("iran_entry_host", "")),
            peers=peers,
        )
        store.validate()
        return store


def load_store(path: Path) -> RelayPeerStore:
    if not path.is_file():
        return RelayPeerStore()
    return RelayPeerStore.from_json(path.read_text(encoding="utf-8"))


def save_store(path: Path, store: RelayPeerStore) -> None:
    store.validate()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(store.to_json(), encoding="utf-8")


def add_peer(store: RelayPeerStore, peer: RelayPeer) -> RelayPeerStore:
    if any(p.name == peer.name for p in store.peers):
        raise ConfigError(f"peer {peer.name!r} already exists")
    out = RelayPeerStore(
        version=store.version,
        iran_entry_host=store.iran_entry_host,
        peers=(*store.peers, peer),
    )
    out.validate()
    return out


def remove_peer(store: RelayPeerStore, name: str) -> RelayPeerStore:
    remaining = tuple(p for p in store.peers if p.name != name)
    if len(remaining) == len(store.peers):
        raise ConfigError(f"no peer named {name!r}")
    out = RelayPeerStore(
        version=store.version,
        iran_entry_host=store.iran_entry_host,
        peers=remaining,
    )
    out.validate()
    return out


def backhaul_for_peer(peer: RelayPeer, password: str, iran_ip: str) -> ww.Backhaul:
    if not iran_ip:
        raise ConfigError("iran_ip required to render peer")
    return ww.Backhaul(
        iran_ip=iran_ip,
        exit_ip=peer.exit_ip,
        password=password,
        cover_sni=peer.cover_sni,
        cover_addr=peer.cover_addr,
        mode=peer.mode,
        user_ports=(peer.user_port,),
        tunnel_port=peer.tunnel_port,
        exit_service="127.0.0.1:443",
    )


def render_peer_configs(peer: RelayPeer, password: str, iran_ip: str) -> tuple[dict, dict]:
    """Iran-side WaterWall config + core.json filename reference."""
    b = backhaul_for_peer(peer, password, iran_ip)
    cfg = ww.render_iran(b)
    core = ww.core_json("config.json")
    return cfg, core


def peer_unit_name(name: str) -> str:
    return f"shahrah-waterwall@{name}.service"


def peer_workdir(base: Path, name: str) -> Path:
    return base / f"peer-{name}"


def systemd_instance_unit(binary: str = "/usr/local/bin/waterwall") -> str:
    return (
        "[Unit]\n"
        "Description=shahrah WaterWall relay peer %i\n"
        "After=network-online.target\nWants=network-online.target\n\n"
        "[Service]\n"
        "WorkingDirectory=/etc/shahrah/waterwall/peer-%i\n"
        f"ExecStart={binary} -c:/etc/shahrah/waterwall/peer-%i/core.json\n"
        "Restart=always\nRestartSec=3\n"
        "AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN\n"
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN\n"
        "NoNewPrivileges=true\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
