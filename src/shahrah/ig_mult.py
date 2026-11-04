"""Instagram (and related social) traffic multiplier for billing.

PasarGuard stores raw byte quotas. Operators often want Instagram CDN traffic to count
at a different rate (e.g. 0.5x) without keeping a permanent browse history.

Shahrah never MITMs. When the opt-in access log is enabled, destination *hit counts*
are used as a share proxy (Xray access lines do not carry byte sizes). The multiplier
is applied only to the estimated Instagram share of each user's raw StatsService total:

    billed = raw * (1 - share) + raw * share * coefficient

Aggregates are computed on demand and discarded with the retention window of
:mod:`shahrah.sni_watch`. No per-URL archive is written.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import sni_watch
from .accounting import UserTraffic
from .models import ConfigError

# Public CDN / product host suffixes — not deployment identifiers.
DEFAULT_INSTAGRAM_SUFFIXES: tuple[str, ...] = (
    "instagram.com",
    "cdninstagram.com",
    "ig.me",
    "igsonar.com",
    "facebook.com",
    "fbcdn.net",
    "fbsbx.com",
)


@dataclass(frozen=True, slots=True)
class IgMultConfig:
    """Operator-tunable multiplier. ``coefficient`` of 1.0 means no change."""

    enabled: bool = False
    coefficient: float = 1.0
    suffixes: tuple[str, ...] = DEFAULT_INSTAGRAM_SUFFIXES

    def __post_init__(self) -> None:
        if not 0.0 <= self.coefficient <= 10.0:
            raise ConfigError("ig-mult coefficient must be between 0 and 10")
        cleaned = tuple(s.strip().lower().rstrip(".") for s in self.suffixes if s.strip())
        if self.enabled and not cleaned:
            raise ConfigError("ig-mult needs at least one domain suffix when enabled")
        object.__setattr__(self, "suffixes", cleaned)

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "coefficient": self.coefficient,
            "suffixes": list(self.suffixes),
        }


def matches_instagram(host: str, suffixes: tuple[str, ...] = DEFAULT_INSTAGRAM_SUFFIXES) -> bool:
    host = host.lower().rstrip(".")
    if not host:
        return False
    parts = host.split(".")
    for index in range(len(parts) - 1):
        if ".".join(parts[index:]) in suffixes:
            return True
    return host in suffixes


def share_from_hits(
    hits: Mapping[str, int], suffixes: tuple[str, ...] = DEFAULT_INSTAGRAM_SUFFIXES
) -> float:
    """Fraction of destination hits that match Instagram-related suffixes."""
    total = sum(hits.values())
    if total <= 0:
        return 0.0
    ig = sum(count for host, count in hits.items() if matches_instagram(host, suffixes))
    return ig / total


@dataclass(frozen=True, slots=True)
class BilledTraffic:
    user: str
    raw_up: int
    raw_down: int
    share: float
    billed_up: int
    billed_down: int
    coefficient: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "user": self.user,
            "raw_uplink": self.raw_up,
            "raw_downlink": self.raw_down,
            "instagram_share": round(self.share, 6),
            "coefficient": self.coefficient,
            "billed_uplink": self.billed_up,
            "billed_downlink": self.billed_down,
        }


def apply_multiplier(traffic: UserTraffic, share: float, coefficient: float) -> BilledTraffic:
    if not 0.0 <= share <= 1.0:
        raise ConfigError("instagram share must be between 0 and 1")
    share = float(share)
    factor = (1.0 - share) + share * coefficient

    def scale(raw: int) -> int:
        return int(raw * factor)

    return BilledTraffic(
        user=traffic.label,
        raw_up=traffic.uplink,
        raw_down=traffic.downlink,
        share=share,
        billed_up=scale(traffic.uplink),
        billed_down=scale(traffic.downlink),
        coefficient=coefficient,
    )


def bill_users(
    raw: Mapping[str, UserTraffic],
    hits_by_user: Mapping[str, Mapping[str, int]],
    config: IgMultConfig,
) -> dict[str, BilledTraffic]:
    """Apply the multiplier per user. Users without hits keep share 0 (raw = billed)."""
    if not config.enabled:
        return {label: apply_multiplier(row, 0.0, 1.0) for label, row in raw.items()}
    out: dict[str, BilledTraffic] = {}
    for label, row in raw.items():
        share = share_from_hits(hits_by_user.get(label, {}), config.suffixes)
        out[label] = apply_multiplier(row, share, config.coefficient)
    return out


def hits_by_user_from_store(store: sni_watch.WatchStore) -> dict[str, dict[str, int]]:
    """Collapse a watch store into ``{user: {domain: hit_count}}``."""
    by_user: dict[str, dict[str, int]] = {}
    for hit in store.hits:
        bucket = by_user.setdefault(hit.user, {})
        bucket[hit.domain] = bucket.get(hit.domain, 0) + 1
    return by_user


def load_config(path: Path) -> IgMultConfig:
    if not path.exists():
        return IgMultConfig()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read ig-mult config: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("ig-mult config must be a JSON object")
    suffixes = data.get("suffixes")
    return IgMultConfig(
        enabled=bool(data.get("enabled", False)),
        coefficient=float(data.get("coefficient", 1.0)),
        suffixes=tuple(suffixes) if suffixes is not None else DEFAULT_INSTAGRAM_SUFFIXES,
    )


def save_config(path: Path, config: IgMultConfig) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(config.as_dict(), indent=2) + "\n"
    path.write_text(text, encoding="utf-8")
    with contextlib.suppress(OSError):
        path.chmod(0o600)


def parse_config_payload(body: Mapping[str, Any]) -> IgMultConfig:
    suffixes = body.get("suffixes")
    return IgMultConfig(
        enabled=bool(body.get("enabled", False)),
        coefficient=float(body.get("coefficient", 1.0)),
        suffixes=tuple(suffixes) if isinstance(suffixes, list) else DEFAULT_INSTAGRAM_SUFFIXES,
    )


@dataclass
class IgMultState:
    """Mutable handle used by the ops console (config path + optional access log)."""

    config_path: Path
    access_log_path: Path | None = None
    retention_hours: float = 48.0
    _config: IgMultConfig = field(default_factory=IgMultConfig)

    def reload(self) -> IgMultConfig:
        self._config = load_config(self.config_path)
        return self._config

    @property
    def config(self) -> IgMultConfig:
        return self._config

    def update(self, config: IgMultConfig) -> IgMultConfig:
        save_config(self.config_path, config)
        self._config = config
        return config

    def estimate(self, raw: Mapping[str, UserTraffic]) -> dict[str, Any]:
        cfg = self._config
        hits: dict[str, dict[str, int]] = {}
        if self.access_log_path is not None and self.access_log_path.exists():
            store = sni_watch.WatchStore(retention_s=self.retention_hours * 3600)
            store.ingest_file(self.access_log_path)
            hits = hits_by_user_from_store(store)
        billed = bill_users(raw, hits, cfg)
        return {
            "config": cfg.as_dict(),
            "users": {label: row.as_dict() for label, row in billed.items()},
            "access_log": str(self.access_log_path) if self.access_log_path else None,
        }
