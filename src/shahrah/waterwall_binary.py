"""WaterWall release asset selection (standard vs old-cpu) with pinned checksums."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .models import ConfigError

WW_VERSION = "v1.5.2"

# Pinned SHA-256 of official GitHub release zips (WaterWall v1.5.2).
WW_SHA256: dict[tuple[str, str], str] = {
    ("x64", "standard"): "1d9ba7da4a3ab42b5685e5ecf03cf3d93a97ede5fd9fce8a12dbfc23e04a829a",
    ("x64", "old-cpu"): "bdd20c083c15bc00df197b2f0562aeba013663230caefc95ca56292b839992b0",
    ("arm64", "standard"): "56486a3a8d02a67f782d45a6155bea4e437348c72611a3f685459d97966ff96b",
    ("arm64", "old-cpu"): "bd553fb76bdc37769854a46e689ca3796b9d2c6258170daaa9d4ef84031a9347",
}

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


def variant_for_asset(arch: str, variant: str) -> tuple[str, str]:
    arch = arch if arch in {"x64", "arm64"} else "x64"
    if variant not in {"standard", "old-cpu"}:
        raise ConfigError(f"unknown WaterWall CPU variant: {variant!r}")
    key = (arch, variant)
    if key not in WW_SHA256:
        raise ConfigError(f"no pinned checksum for arch={arch} variant={variant}")
    suffix = "-old-cpu" if variant == "old-cpu" else ""
    asset = f"Waterwall-linux-gcc-{arch}{suffix}.zip"
    return asset, WW_SHA256[key]


def infer_variant_from_binary(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = _sha256_file(path)
    for (_arch, variant), expected in WW_SHA256.items():
        if digest == expected:
            return variant
    return None


def resolve_cpu_variant(
    *,
    arch: str,
    requested: str = "auto",
    persist_path: Path | None = PERSIST_DEFAULT,
    installed_binary: Path | None = Path("/usr/local/bin/waterwall"),
    cpuinfo_text: str | None = None,
) -> str:
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

    if installed_binary and installed_binary.is_file():
        inferred = infer_variant_from_binary(installed_binary)
        if inferred:
            return inferred

    if persist_path and persist_path.is_file():
        saved = persist_path.read_text(encoding="utf-8").strip().lower()
        if saved in {"standard", "old-cpu"}:
            if arch == "x64" and saved == "standard" and not cpu_has_avx2(cpuinfo_text):
                return "old-cpu"
            return saved

    if arch == "arm64":
        return "standard"

    return "standard" if cpu_has_avx2(cpuinfo_text) else "old-cpu"


def persist_cpu_variant(variant: str, persist_path: Path = PERSIST_DEFAULT) -> None:
    if variant not in {"standard", "old-cpu"}:
        raise ConfigError(f"cannot persist invalid variant {variant!r}")
    persist_path.parent.mkdir(parents=True, exist_ok=True)
    persist_path.write_text(variant + "\n", encoding="utf-8")
