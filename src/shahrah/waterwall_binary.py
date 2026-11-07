"""WaterWall release asset selection (standard vs old-cpu) with pinned checksums."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .models import ConfigError

WW_VERSION = "v1.5.2"

# Pinned SHA-256 of official GitHub release **zip** archives (WaterWall v1.5.2).
WW_ZIP_SHA256: dict[tuple[str, str], str] = {
    ("x64", "standard"): "1d9ba7da4a3ab42b5685e5ecf03cf3d93a97ede5fd9fce8a12dbfc23e04a829a",
    ("x64", "old-cpu"): "bdd20c083c15bc00df197b2f0562aeba013663230caefc95ca56292b839992b0",
    ("arm64", "standard"): "56486a3a8d02a67f782d45a6155bea4e437348c72611a3f685459d97966ff96b",
    ("arm64", "old-cpu"): "bd553fb76bdc37769854a46e689ca3796b9d2c6258170daaa9d4ef84031a9347",
}

# Pinned SHA-256 of the **Waterwall** ELF inside those zips (x64 v1.5.2 only; arm uses zip verify).
WW_ELF_SHA256: dict[tuple[str, str], str] = {
    ("x64", "standard"): "73f71f91a7007aa3eb29e107e55088f694cc532bee6fc9114be1dc780ee36fa0",
    ("x64", "old-cpu"): "7bd06afa62f211cd94d0ff93165af0955a2e86401889d96d3460da074eabe67c",
}

VALID_ARCHES = frozenset({"x64", "arm64"})
VARIANTS = frozenset({"standard", "old-cpu", "auto"})
PERSIST_DEFAULT = Path("/etc/shahrah/waterwall-cpu.variant")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cpu_has_avx2(cpuinfo_text: str | None = None) -> bool:
    if cpuinfo_text is None:
        text = Path("/proc/cpuinfo").read_text(encoding="utf-8")
    else:
        text = cpuinfo_text
    return "avx2" in text.lower()


def variant_for_asset(arch: str, variant: str) -> tuple[str, str, str]:
    """Return (asset_filename, zip_sha256, elf_sha256_or_empty)."""
    if arch not in VALID_ARCHES:
        raise ConfigError(f"unsupported WaterWall arch: {arch!r}")
    if variant not in {"standard", "old-cpu"}:
        raise ConfigError(f"unknown WaterWall CPU variant: {variant!r}")
    zip_key = (arch, variant)
    if zip_key not in WW_ZIP_SHA256:
        raise ConfigError(f"no pinned zip checksum for arch={arch} variant={variant}")
    suffix = "-old-cpu" if variant == "old-cpu" else ""
    asset = f"Waterwall-linux-gcc-{arch}{suffix}.zip"
    elf = WW_ELF_SHA256.get(zip_key, "")
    return asset, WW_ZIP_SHA256[zip_key], elf


def verify_installed_binary(path: Path, *, arch: str, variant: str) -> bool:
    """True when the on-disk ELF matches pinned digest for this arch/variant (if pinned)."""
    if not path.is_file() or not os.access(path, os.X_OK):
        return False
    key = (arch, variant)
    expected_elf = WW_ELF_SHA256.get(key)
    if not expected_elf:
        return True
    return _sha256_file(path) == expected_elf


def resolve_cpu_variant(
    *,
    arch: str,
    requested: str = "auto",
    persist_path: Path | None = PERSIST_DEFAULT,
    cpuinfo_text: str | None = None,
) -> str:
    if arch not in VALID_ARCHES:
        raise ConfigError(f"unsupported WaterWall arch: {arch!r}")
    req = (requested or "auto").strip().lower()
    if req not in VARIANTS:
        raise ConfigError(f"--ww-cpu-variant must be one of {sorted(VARIANTS)}")

    if req != "auto":
        if arch == "x64" and req == "standard" and not cpu_has_avx2(cpuinfo_text):
            raise ConfigError(
                "refusing standard WaterWall on CPU without AVX2; "
                "use --ww-cpu-variant old-cpu or auto"
            )
        return req

    if persist_path and persist_path.is_file():
        saved = persist_path.read_text(encoding="utf-8").strip().lower()
        if saved in {"standard", "old-cpu"}:
            if arch == "x64" and saved == "standard" and not cpu_has_avx2(cpuinfo_text):
                return "old-cpu"
            return saved

    if arch == "arm64":
        return "standard"

    return "standard" if cpu_has_avx2(cpuinfo_text) else "old-cpu"


def should_skip_waterwall_download(
    *,
    arch: str,
    variant: str,
    persist_path: Path | None,
    installed: Path,
) -> bool:
    """Skip re-download when persisted choice matches resolved variant and ELF verifies."""
    if persist_path is None or not persist_path.is_file():
        return False
    saved = persist_path.read_text(encoding="utf-8").strip().lower()
    if saved != variant:
        return False
    return verify_installed_binary(installed, arch=arch, variant=variant)


def persist_cpu_variant(variant: str, persist_path: Path = PERSIST_DEFAULT) -> None:
    if variant not in {"standard", "old-cpu"}:
        raise ConfigError(f"cannot persist invalid variant {variant!r}")
    persist_path.parent.mkdir(parents=True, exist_ok=True)
    persist_path.write_text(variant + "\n", encoding="utf-8")
