"""Paths and units owned by a Shahrah install (uninstall scope)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .models import ConfigError

# Units we may stop/disable — never ssh, docker, nginx, caddy, unrelated panels.
OWNED_SYSTEMD_UNITS: tuple[str, ...] = (
    "shahrah-xray",
    "shahrah-waterwall",
    "shahrah-waterwall@",
    "shahrah-hysteria2",
    "shahrah-paqet",
    "shahrah-paqet-client",
    "shahrah-brain",
    "shahrah-serve-sub",
    "shahrah-rootit",
    "wg-quick@warp",
)

OWNED_PATH_PREFIXES: tuple[str, ...] = (
    "/etc/shahrah",
    "/opt/shahrah",
    "/var/lib/shahrah",
    "/usr/local/bin/shahrah",
    "/usr/local/bin/waterwall",
    "/usr/local/bin/xray",
)

SYSCTL_DROP_IN = Path("/etc/sysctl.d/99-shahrah.conf")
RESOLVED_DROP_IN = Path("/etc/systemd/resolved.conf.d/90-shahrah.conf")


def assert_safe_path(path: Path) -> None:
    text = str(path.resolve() if path.is_absolute() else path)
    if ".." in path.parts:
        raise ConfigError(f"refusing unsafe path: {path!r}")
    if path.is_symlink():
        raise ConfigError(f"refusing symlink path in uninstall plan: {path!r}")
    for prefix in OWNED_PATH_PREFIXES:
        if text == prefix or text.startswith(prefix + "/"):
            return
    raise ConfigError(f"path outside shahrah ownership: {path!r}")


@dataclass(slots=True)
class InstallManifest:
    version: int = 1
    units: list[str] = field(default_factory=lambda: list(OWNED_SYSTEMD_UNITS))
    paths: list[str] = field(default_factory=lambda: list(OWNED_PATH_PREFIXES))
    managed_ufw: bool = True
    preinstall_snapshot: str = "/var/lib/shahrah/preinstall.snapshot"

    def to_json(self) -> str:
        return (
            json.dumps(
                {
                    "version": self.version,
                    "units": self.units,
                    "paths": self.paths,
                    "managed_ufw": self.managed_ufw,
                    "preinstall_snapshot": self.preinstall_snapshot,
                },
                indent=2,
            )
            + "\n"
        )

    @classmethod
    def from_json(cls, text: str) -> InstallManifest:
        data = json.loads(text)
        return cls(
            version=int(data.get("version", 1)),
            units=list(data.get("units", OWNED_SYSTEMD_UNITS)),
            paths=list(data.get("paths", OWNED_PATH_PREFIXES)),
            managed_ufw=bool(data.get("managed_ufw", True)),
            preinstall_snapshot=str(
                data.get("preinstall_snapshot", "/var/lib/shahrah/preinstall.snapshot")
            ),
        )


def default_manifest() -> InstallManifest:
    return InstallManifest()


def plan_removal(
    manifest: InstallManifest,
    *,
    purge_data: bool,
    extra_peer_dirs: tuple[Path, ...] = (),
) -> tuple[list[str], list[str]]:
    """Return (units_to_stop, paths_to_remove) without executing anything."""
    units = [u for u in manifest.units if u]
    paths: list[str] = []
    if purge_data:
        for p in manifest.paths:
            assert_safe_path(Path(p))
            paths.append(p)
        for peer in extra_peer_dirs:
            assert_safe_path(peer)
            paths.append(str(peer))
        paths.append(str(SYSCTL_DROP_IN))
        # Only if we created it — caller checks existence
        paths.append(str(RESOLVED_DROP_IN))
    return units, paths
