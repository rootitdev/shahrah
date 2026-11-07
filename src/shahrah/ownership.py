"""Shahrah install ownership: manifest, uninstall plan, binary provenance."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .models import ConfigError

# Exact unit names or template bases (suffix @) we manage — never arbitrary manifest strings.
UNIT_ALLOWLIST: frozenset[str] = frozenset(
    {
        "shahrah-xray",
        "shahrah-waterwall",
        "shahrah-waterwall@",
        "shahrah-waterwall-exit@",
        "shahrah-hysteria2",
        "shahrah-paqet",
        "shahrah-paqet-client",
        "shahrah-brain",
        "shahrah-serve-sub",
        "shahrah-rootit",
        "wg-quick@warp",
    }
)

TEMPLATE_BASE = "shahrah-waterwall@"
TEMPLATE_EXIT_BASE = "shahrah-waterwall-exit@"

UNIT_FILES: dict[str, str] = {
    "shahrah-xray": "/etc/systemd/system/shahrah-xray.service",
    "shahrah-waterwall": "/etc/systemd/system/shahrah-waterwall.service",
    "shahrah-waterwall@": "/etc/systemd/system/shahrah-waterwall@.service",
    "shahrah-hysteria2": "/etc/systemd/system/shahrah-hysteria2.service",
    "shahrah-paqet": "/etc/systemd/system/shahrah-paqet.service",
    "shahrah-paqet-client": "/etc/systemd/system/shahrah-paqet-client.service",
    "shahrah-brain": "/etc/systemd/system/shahrah-brain.service",
    "shahrah-serve-sub": "/etc/systemd/system/shahrah-serve-sub.service",
    "shahrah-rootit": "/etc/systemd/system/shahrah-rootit.service",
}

# Data trees only — binaries handled via provenance.
PURGE_DIR_PATHS: tuple[str, ...] = (
    "/etc/shahrah",
    "/opt/shahrah",
    "/var/lib/shahrah",
)

DROP_INS: tuple[str, ...] = (
    "/etc/sysctl.d/99-shahrah.conf",
    "/etc/systemd/resolved.conf.d/90-shahrah.conf",
)

CLI_SYMLINK = "/usr/local/bin/shahrah"

PROVENANCE_PATH = Path("/var/lib/shahrah/binary-provenance.json")
_MANIFEST_UNIT_RE = re.compile(r"^shahrah-[a-z0-9-]+(@)?$|^wg-quick@warp$|^shahrah-waterwall-exit@")


def validate_unit_name(name: str) -> str:
    base = name.removesuffix(".service")
    if base in UNIT_ALLOWLIST:
        return base
    for prefix in (TEMPLATE_BASE, TEMPLATE_EXIT_BASE):
        if base.startswith(prefix):
            suffix = base[len(prefix) :]
            if suffix.replace("-", "").isalnum() and suffix:
                return base
    raise ConfigError(f"unit not in shahrah managed allowlist: {name!r}")


def assert_safe_path(path: Path) -> None:
    if ".." in path.parts:
        raise ConfigError(f"refusing unsafe path: {path!r}")
    if path.is_symlink():
        raise ConfigError(f"refusing symlink in uninstall plan: {path!r}")
    text = str(path)
    allowed = PURGE_DIR_PATHS + DROP_INS + (CLI_SYMLINK,)
    for prefix in allowed:
        if text == prefix or text.startswith(prefix.rstrip("/") + "/"):
            return
    raise ConfigError(f"path outside shahrah ownership: {path!r}")


@dataclass(slots=True)
class BinaryProvenanceEntry:
    path: str
    kind: str
    sha256: str
    installed_utc: str

    def matches_file(self) -> bool:
        p = Path(self.path)
        if not p.is_file() or p.is_symlink():
            return False
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        return digest == self.sha256


@dataclass(slots=True)
class InstallManifest:
    version: int = 2
    units: list[str] = field(default_factory=lambda: sorted(UNIT_ALLOWLIST))
    managed_ufw: bool = True
    ssh_port: int | None = None
    public_ports: list[int] = field(default_factory=list)
    preinstall_snapshot: str = "/var/lib/shahrah/preinstall.snapshot"

    def to_json(self) -> str:
        return (
            json.dumps(
                {
                    "version": self.version,
                    "units": self.sanitized_units(),
                    "managed_ufw": self.managed_ufw,
                    "ssh_port": self.ssh_port,
                    "public_ports": self.public_ports,
                    "preinstall_snapshot": self.preinstall_snapshot,
                },
                indent=2,
            )
            + "\n"
        )

    def sanitized_units(self) -> list[str]:
        out: list[str] = []
        for name in self.units:
            out.append(validate_unit_name(name))
        return sorted(set(out))

    @classmethod
    def from_json(cls, text: str) -> InstallManifest:
        data = json.loads(text)
        raw_units = list(data.get("units", []))
        for name in raw_units:
            if not _MANIFEST_UNIT_RE.match(name.removesuffix(".service")):
                raise ConfigError(f"manifest unit rejected by pattern: {name!r}")
            validate_unit_name(name)
        return cls(
            version=int(data.get("version", 1)),
            units=raw_units,
            managed_ufw=bool(data.get("managed_ufw", True)),
            ssh_port=int(data["ssh_port"]) if data.get("ssh_port") is not None else None,
            public_ports=[int(p) for p in data.get("public_ports", [])],
            preinstall_snapshot=str(
                data.get("preinstall_snapshot", "/var/lib/shahrah/preinstall.snapshot")
            ),
        )


def default_manifest() -> InstallManifest:
    return InstallManifest()


def load_provenance(path: Path = PROVENANCE_PATH) -> list[BinaryProvenanceEntry]:
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return [BinaryProvenanceEntry(**item) for item in data.get("entries", [])]


def provenance_removable_binaries(entries: list[BinaryProvenanceEntry]) -> list[str]:
    out: list[str] = []
    for entry in entries:
        if entry.path in ("/usr/local/bin/xray", "/usr/local/bin/waterwall"):
            try:
                assert_safe_path(Path(entry.path))
            except ConfigError:
                continue
            if entry.matches_file():
                out.append(entry.path)
    return out


def ufw_delete_scoped(
    public_ports: list[int], *, tunnel_rules: list[str] | None = None
) -> list[str]:
    """Delete only VPN-related allows — never ``ufw disable`` or SSH rules."""
    cmds: list[str] = []
    for port in sorted(set(public_ports)):
        cmds.append(f"ufw delete allow {port}/tcp")
    for rule in tunnel_rules or []:
        if rule.startswith("ufw delete "):
            cmds.append(rule)
    return cmds


def _unit_files_for_units(units: list[str]) -> list[str]:
    files: list[str] = []
    for unit in units:
        base = validate_unit_name(unit)
        if base.endswith("@"):
            path = UNIT_FILES.get(base)
            if path:
                files.append(path)
            continue
        if base.startswith(TEMPLATE_BASE):
            files.append(f"/etc/systemd/system/{base}.service")
            continue
        path = UNIT_FILES.get(base)
        if path:
            files.append(path)
    return sorted(set(files))


def build_uninstall_plan(
    manifest: InstallManifest,
    *,
    purge_data: bool,
    peer_workdirs: tuple[Path, ...] = (),
    provenance: list[BinaryProvenanceEntry] | None = None,
    extra_tunnel_ufw_deletes: list[str] | None = None,
) -> dict[str, object]:
    units = manifest.sanitized_units()
    unit_files = _unit_files_for_units(units)
    ufw_delete: list[str] = []
    if manifest.managed_ufw and manifest.public_ports:
        ufw_delete = ufw_delete_scoped(
            manifest.public_ports,
            tunnel_rules=extra_tunnel_ufw_deletes,
        )

    paths: list[str] = []
    binaries: list[str] = []
    backup_paths = ["/etc/shahrah", "/var/lib/shahrah"]

    if purge_data:
        for p in PURGE_DIR_PATHS:
            assert_safe_path(Path(p))
            paths.append(p)
        for peer in peer_workdirs:
            assert_safe_path(peer)
            paths.append(str(peer))
        for drop in DROP_INS:
            paths.append(drop)
        if provenance:
            binaries = provenance_removable_binaries(provenance)
        paths.append(CLI_SYMLINK)

    return {
        "version": 2,
        "units": units,
        "unit_files": unit_files,
        "ufw_delete": ufw_delete,
        "paths": paths,
        "binaries": binaries,
        "backup_paths": backup_paths,
        "purge": purge_data,
        "note": (
            "Does not disable ufw globally, remove SSH, "
            "or delete binaries without provenance match."
        ),
    }


def enrich_manifest_from_state(manifest: InstallManifest, state_path: Path) -> InstallManifest:
    """Fill public_ports from live state.json for uninstall UFW scoping."""
    if not state_path.is_file():
        return manifest
    from .state import load_state

    state = load_state(state_path)
    ports = [item.port for item in state.server_settings().listeners()]
    return InstallManifest(
        version=manifest.version,
        units=manifest.units,
        managed_ufw=manifest.managed_ufw,
        ssh_port=manifest.ssh_port,
        public_ports=ports,
        preinstall_snapshot=manifest.preinstall_snapshot,
    )


def record_provenance_json(path: Path, kind: str, sha256: str, installed_utc: str) -> str:
    entries = load_provenance(PROVENANCE_PATH)
    entries = [e for e in entries if e.path != path]
    entries.append(
        BinaryProvenanceEntry(path=path, kind=kind, sha256=sha256, installed_utc=installed_utc)
    )
    payload = {"entries": [asdict(e) for e in entries]}
    PROVENANCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2) + "\n"
    PROVENANCE_PATH.write_text(text, encoding="utf-8")
    return text
