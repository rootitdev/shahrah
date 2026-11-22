"""Multi-path Iran↔exit backhaul: health, manual select, and automatic failover.

Shahrah's user data plane stays REALITY on Iran:443; this module only steers the
operator leg between Iran and one or more exits (WaterWall modes, optional SSH fallback).
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from . import waterwall as ww
from .models import ConfigError
from .state import write_private_file

DEFAULT_STORE = Path("/etc/shahrah/backhaul-failover.json")
FAIL_STREAK = 3
RECOVER_STREAK = 5
WW_UNIT = ww.UNIT

PATH_CATALOG: dict[str, dict[str, str]] = {
    "waterwall-reverse": {
        "title": "WaterWall reverse",
        "title_fa": "واترول — حالت reverse (خروج به ایران وصل می‌شود)",
        "kind": "waterwall",
        "mode": "reverse",
    },
    "waterwall-direct": {
        "title": "WaterWall direct",
        "title_fa": "واترول — حالت direct (ایران به خروج وصل می‌شود)",
        "kind": "waterwall",
        "mode": "direct",
    },
    "waterwall-alt": {
        "title": "WaterWall alternate tunnel",
        "title_fa": "واترول — پورت/کاور جایگزین",
        "kind": "waterwall",
        "mode": "reverse",
    },
    "ssh-fallback": {
        "title": "SSH autossh bridge",
        "title_fa": "پل اضطراری SSH (admin/smoke)",
        "kind": "ssh",
        "mode": "",
    },
    "paqet-client": {
        "title": "paqet crisis client",
        "title_fa": "paqet اضطراری (SOCKS؛ جایگزین مستقیم 443 نیست)",
        "kind": "paqet",
        "mode": "",
    },
}

DEFAULT_PRIORITY: tuple[str, ...] = (
    "waterwall-reverse",
    "waterwall-direct",
    "waterwall-alt",
    "ssh-fallback",
)


@dataclass(slots=True)
class WaterWallParams:
    workdir: Path = Path("/etc/shahrah/waterwall")
    key_file: Path = Path("/etc/shahrah/backhaul.key")
    iran_ip: str = ""
    exit_ip: str = ""
    tunnel_port: int = 8443
    alt_tunnel_port: int = 8444
    cover_sni: str = "www.speedtest.net"
    cover_addr: str = ""
    alt_cover_sni: str = ""
    side: str = "iran"
    exit_service: str = "127.0.0.1:443"

    def validate(self) -> None:
        if self.side not in ("iran", "exit"):
            raise ConfigError("waterwall.side must be iran or exit")
        if not self.iran_ip or not self.exit_ip:
            raise ConfigError("waterwall needs iran_ip and exit_ip (run `shahrah backhaul init`)")
        if not self.key_file.is_file():
            raise ConfigError(f"missing backhaul key: {self.key_file}")


@dataclass(slots=True)
class BackhaulStore:
    version: int = 1
    control: str = "auto"  # auto | manual
    active: str = "waterwall-reverse"
    priority: tuple[str, ...] = DEFAULT_PRIORITY
    waterwall: WaterWallParams = field(default_factory=WaterWallParams)
    fail_streak: int = 0
    success_streak: int = 0
    last_failover_at: float = 0.0
    history: tuple[dict[str, Any], ...] = ()

    def validate(self) -> None:
        if self.active not in PATH_CATALOG:
            raise ConfigError(f"unknown active path: {self.active}")
        for p in self.priority:
            if p not in PATH_CATALOG:
                raise ConfigError(f"unknown priority path: {p}")
        self.waterwall.validate()

    def to_json(self) -> str:
        data = {
            "version": self.version,
            "control": self.control,
            "active": self.active,
            "priority": list(self.priority),
            "waterwall": {
                "workdir": str(self.waterwall.workdir),
                "key_file": str(self.waterwall.key_file),
                "iran_ip": self.waterwall.iran_ip,
                "exit_ip": self.waterwall.exit_ip,
                "tunnel_port": self.waterwall.tunnel_port,
                "alt_tunnel_port": self.waterwall.alt_tunnel_port,
                "cover_sni": self.waterwall.cover_sni,
                "cover_addr": self.waterwall.cover_addr,
                "alt_cover_sni": self.waterwall.alt_cover_sni,
                "side": self.waterwall.side,
                "exit_service": self.waterwall.exit_service,
            },
            "fail_streak": self.fail_streak,
            "success_streak": self.success_streak,
            "last_failover_at": self.last_failover_at,
            "history": list(self.history[-50:]),
        }
        return json.dumps(data, indent=2) + "\n"

    @classmethod
    def from_json(cls, text: str) -> BackhaulStore:
        data = json.loads(text)
        w = data.get("waterwall") or {}
        store = cls(
            version=int(data.get("version", 1)),
            control=str(data.get("control", "auto")),
            active=str(data.get("active", "waterwall-reverse")),
            priority=tuple(data.get("priority") or DEFAULT_PRIORITY),
            waterwall=WaterWallParams(
                workdir=Path(w.get("workdir", "/etc/shahrah/waterwall")),
                key_file=Path(w.get("key_file", "/etc/shahrah/backhaul.key")),
                iran_ip=str(w.get("iran_ip", "")),
                exit_ip=str(w.get("exit_ip", "")),
                tunnel_port=int(w.get("tunnel_port", 8443)),
                alt_tunnel_port=int(w.get("alt_tunnel_port", 8444)),
                cover_sni=str(w.get("cover_sni", "www.speedtest.net")),
                cover_addr=str(w.get("cover_addr", "")),
                alt_cover_sni=str(w.get("alt_cover_sni", "")),
                side=str(w.get("side", "iran")),
                exit_service=str(w.get("exit_service", "127.0.0.1:443")),
            ),
            fail_streak=int(data.get("fail_streak", 0)),
            success_streak=int(data.get("success_streak", 0)),
            last_failover_at=float(data.get("last_failover_at", 0.0)),
            history=tuple(data.get("history") or ()),
        )
        store.validate()
        return store


def load_store(path: Path = DEFAULT_STORE) -> BackhaulStore:
    if not path.is_file():
        raise ConfigError(f"backhaul store missing: {path} (run `shahrah backhaul init`)")
    return BackhaulStore.from_json(path.read_text(encoding="utf-8"))


def save_store(store: BackhaulStore, path: Path = DEFAULT_STORE) -> None:
    store.validate()
    write_private_file(path, store.to_json())
    try:
        path.chmod(0o640)
    except OSError:
        pass


def _systemd_active(unit: str) -> bool:
    try:
        out = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True,
            text=True,
            timeout=8,
        )
        return out.stdout.strip() == "active"
    except (OSError, subprocess.TimeoutExpired):
        return False


def _read_password(key_file: Path) -> str:
    raw = key_file.read_bytes()
    if not (16 <= len(raw) <= 32):
        raise ConfigError("backhaul key must be 16..32 bytes")
    return raw.decode("latin-1")


def _backhaul_for(store: BackhaulStore, path_id: str) -> ww.Backhaul:
    w = store.waterwall
    password = _read_password(w.key_file)
    mode = PATH_CATALOG[path_id].get("mode") or "reverse"
    tunnel = w.tunnel_port
    cover = w.cover_sni
    cover_addr = w.cover_addr
    if path_id == "waterwall-alt":
        tunnel = w.alt_tunnel_port
        cover = w.alt_cover_sni or w.cover_sni
    return ww.Backhaul(
        iran_ip=w.iran_ip,
        exit_ip=w.exit_ip,
        password=password,
        cover_sni=cover,
        cover_addr=cover_addr,
        mode=mode,
        tunnel_port=tunnel,
        exit_service=w.exit_service,
    )


def render_waterwall_configs(store: BackhaulStore, path_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    bh = _backhaul_for(store, path_id)
    side = store.waterwall.side
    if side == "iran":
        cfg = ww.render_iran(bh)
        core = ww.core_json("config.json")
        return cfg, core
    cfg = ww.render_exit(bh)
    core = ww.core_json("config.json")
    return cfg, core


def apply_path(store: BackhaulStore, path_id: str) -> None:
    meta = PATH_CATALOG.get(path_id)
    if not meta:
        raise ConfigError(f"unknown path: {path_id}")
    kind = meta["kind"]
    if kind == "waterwall":
        wdir = store.waterwall.workdir
        wdir.mkdir(parents=True, exist_ok=True)
        cfg, core = render_waterwall_configs(store, path_id)
        write_private_file(wdir / "config.json", ww.dumps(cfg))
        write_private_file(wdir / "core.json", ww.dumps(core))
        subprocess.run(["systemctl", "daemon-reload"], check=False, timeout=30)
        subprocess.run(["systemctl", "restart", WW_UNIT], check=True, timeout=60)
    elif kind == "ssh":
        subprocess.run(["systemctl", "enable", "--now", "shahrah-ssh-fallback"], check=False, timeout=30)
        subprocess.run(["systemctl", "restart", "shahrah-ssh-fallback"], check=True, timeout=60)
    elif kind == "paqet":
        subprocess.run(["systemctl", "enable", "--now", "shahrah-paqet-client"], check=False, timeout=30)
        subprocess.run(["systemctl", "restart", "shahrah-paqet-client"], check=True, timeout=60)
    else:
        raise ConfigError(f"unsupported path kind: {kind}")


def path_health(path_id: str) -> bool:
    meta = PATH_CATALOG.get(path_id)
    if not meta:
        return False
    kind = meta["kind"]
    if kind == "waterwall":
        return _systemd_active(WW_UNIT)
    if kind == "ssh":
        return _systemd_active("shahrah-ssh-fallback")
    if kind == "paqet":
        return _systemd_active("shahrah-paqet-client")
    return False


def status_report(store: BackhaulStore) -> dict[str, Any]:
    paths = []
    for pid in store.priority:
        cat = PATH_CATALOG[pid]
        paths.append(
            {
                "id": pid,
                "title": cat["title"],
                "title_fa": cat["title_fa"],
                "healthy": path_health(pid),
                "active": pid == store.active,
            }
        )
    return {
        "control": store.control,
        "active": store.active,
        "fail_streak": store.fail_streak,
        "success_streak": store.success_streak,
        "last_failover_at": store.last_failover_at,
        "priority": list(store.priority),
        "paths": paths,
        "waterwall_unit": WW_UNIT,
        "waterwall_active": _systemd_active(WW_UNIT),
    }


def set_active(store: BackhaulStore, path_id: str, *, manual: bool = True) -> BackhaulStore:
    if path_id not in PATH_CATALOG:
        raise ConfigError(f"unknown path: {path_id}")
    apply_path(store, path_id)
    hist = list(store.history)
    hist.append({"ts": time.time(), "path": path_id, "manual": manual})
    updated = replace(
        store,
        active=path_id,
        control="manual" if manual else store.control,
        fail_streak=0,
        success_streak=0,
        history=tuple(hist[-50:]),
    )
    return updated


def set_auto(store: BackhaulStore) -> BackhaulStore:
    return replace(store, control="auto", fail_streak=0, success_streak=0)


def _next_priority(store: BackhaulStore, after: str) -> str | None:
    order = list(store.priority)
    if after not in order:
        return order[0] if order else None
    idx = order.index(after)
    for candidate in order[idx + 1 :]:
        if path_health(candidate) or candidate != after:
            return candidate
    for candidate in order:
        if candidate != after:
            return candidate
    return None


def failover_once(store: BackhaulStore) -> tuple[BackhaulStore, str]:
    """One auto cycle: track health of active path; switch after FAIL_STREAK unhealthy."""
    if store.control != "auto":
        return store, "skipped (manual control)"

    healthy = path_health(store.active)
    if healthy:
        store = replace(store, fail_streak=0, success_streak=store.success_streak + 1)
        if store.success_streak >= RECOVER_STREAK:
            first = store.priority[0]
            if store.active != first and path_health(first):
                store = set_active(store, first, manual=False)
                store = replace(store, control="auto", success_streak=0)
                return store, f"failback to {first}"
        return store, "ok"

    store = replace(store, success_streak=0, fail_streak=store.fail_streak + 1)
    if store.fail_streak < FAIL_STREAK:
        return store, f"degraded ({store.fail_streak}/{FAIL_STREAK})"

    nxt = _next_priority(store, store.active)
    if not nxt:
        return store, "no_fallback"
    try:
        store = set_active(store, nxt, manual=False)
        store = replace(
            store,
            control="auto",
            fail_streak=0,
            success_streak=0,
            last_failover_at=time.time(),
        )
        return store, f"switched to {nxt}"
    except (OSError, subprocess.CalledProcessError, ConfigError) as exc:
        return store, f"switch_failed: {exc}"


def init_store(
    *,
    side: str,
    iran_ip: str,
    exit_ip: str,
    tunnel_port: int = 8443,
    cover_sni: str = "www.speedtest.net",
    cover_addr: str = "",
    exit_service: str = "127.0.0.1:443",
    key_file: Path | None = None,
    workdir: Path | None = None,
    path: Path = DEFAULT_STORE,
    force: bool = False,
    alt_tunnel_port: int = 8444,
) -> BackhaulStore:
    if path.is_file() and not force:
        return load_store(path)
    key = key_file or Path("/etc/shahrah/backhaul.key")
    store = BackhaulStore(
        waterwall=WaterWallParams(
            side=side,
            iran_ip=iran_ip,
            exit_ip=exit_ip,
            tunnel_port=tunnel_port,
            alt_tunnel_port=alt_tunnel_port,
            cover_sni=cover_sni,
            cover_addr=cover_addr,
            exit_service=exit_service,
            key_file=key,
            workdir=workdir or Path("/etc/shahrah/waterwall"),
        ),
        active="waterwall-reverse",
        control="auto",
    )
    save_store(store, path)
    return store


def failover_systemd_unit() -> str:
    return (
        "[Unit]\n"
        "Description=Shahrah backhaul automatic failover (one shot)\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "Environment=PYTHONUNBUFFERED=1\n"
        "ExecStart=/usr/local/bin/shahrah backhaul failover-once\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def failover_systemd_timer() -> str:
    return (
        "[Unit]\n"
        "Description=Run Shahrah backhaul failover every 15s\n"
        "\n"
        "[Timer]\n"
        "OnBootSec=45s\n"
        "OnUnitActiveSec=15s\n"
        "AccuracySec=1s\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )