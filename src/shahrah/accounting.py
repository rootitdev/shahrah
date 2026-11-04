"""Per-user traffic accounting from Xray's loopback StatsService.

Independent Shahrah nodes (not panel-managed) expose StatsService on ``127.0.0.1`` only.
This module queries it via the ``xray api statsquery`` CLI so the runtime stays
stdlib-only (no gRPC dependency). PasarGuard nodes keep their own accounting; do not
enable the local stats API on those cores.

Stat names follow Xray's convention::

    user>>><label>>>traffic>>>uplink
    user>>><label>>>traffic>>>downlink

Counters are cumulative until reset. ``delta_since`` compares two snapshots for billing
export without clearing the live counters.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .models import ConfigError

STAT_NAME_RE = re.compile(r"^user>>>(?P<label>[^>]+)>>>traffic>>>(?P<direction>uplink|downlink)$")
DEFAULT_STATS_SERVER = "127.0.0.1:10085"


@dataclass(frozen=True, slots=True)
class UserTraffic:
    label: str
    uplink: int = 0
    downlink: int = 0

    def __post_init__(self) -> None:
        if self.uplink < 0 or self.downlink < 0:
            raise ConfigError("traffic counters must be non-negative")

    @property
    def total(self) -> int:
        return self.uplink + self.downlink

    def plus(self, other: UserTraffic) -> UserTraffic:
        if other.label != self.label:
            raise ConfigError("cannot add traffic for different users")
        return UserTraffic(self.label, self.uplink + other.uplink, self.downlink + other.downlink)

    def minus(self, other: UserTraffic) -> UserTraffic:
        if other.label != self.label:
            raise ConfigError("cannot subtract traffic for different users")
        return UserTraffic(
            self.label,
            max(0, self.uplink - other.uplink),
            max(0, self.downlink - other.downlink),
        )

    def as_dict(self) -> dict[str, int | str]:
        return {
            "label": self.label,
            "uplink": self.uplink,
            "downlink": self.downlink,
            "total": self.total,
        }


def parse_stat_name(name: str) -> tuple[str, str] | None:
    match = STAT_NAME_RE.match(name.strip())
    if not match:
        return None
    return match.group("label"), match.group("direction")


def parse_stats_payload(payload: Mapping[str, Any] | Sequence[Any]) -> dict[str, UserTraffic]:
    """Turn an Xray ``statsquery`` JSON body into per-label traffic."""
    rows: Sequence[Any]
    if isinstance(payload, Mapping):
        rows = payload.get("stat") or payload.get("stats") or ()
    else:
        rows = payload
    uplink: dict[str, int] = {}
    downlink: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        parsed = parse_stat_name(str(row.get("name", "")))
        if parsed is None:
            continue
        label, direction = parsed
        try:
            value = int(row.get("value", 0))
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"non-integer stat value for {label!r}") from exc
        if value < 0:
            raise ConfigError(f"negative stat value for {label!r}")
        if direction == "uplink":
            uplink[label] = uplink.get(label, 0) + value
        else:
            downlink[label] = downlink.get(label, 0) + value
    labels = sorted(set(uplink) | set(downlink))
    return {
        label: UserTraffic(label, uplink.get(label, 0), downlink.get(label, 0)) for label in labels
    }


def delta_since(
    current: Mapping[str, UserTraffic], previous: Mapping[str, UserTraffic]
) -> dict[str, UserTraffic]:
    """Bytes transferred since ``previous`` (counters that reset appear as full current)."""
    labels = sorted(set(current) | set(previous))
    out: dict[str, UserTraffic] = {}
    for label in labels:
        now = current.get(label, UserTraffic(label))
        was = previous.get(label, UserTraffic(label))
        if now.uplink < was.uplink or now.downlink < was.downlink:
            # Counter was reset on the Xray side; treat the new reading as the period total.
            out[label] = now
        else:
            out[label] = now.minus(was)
    return out


def query_stats(
    *,
    xray_bin: str = "xray",
    server: str = DEFAULT_STATS_SERVER,
    reset: bool = False,
    timeout_s: float = 10.0,
) -> dict[str, UserTraffic]:
    """Run ``xray api statsquery`` against the loopback StatsService."""
    if "://" in server or "/" in server:
        raise ConfigError("stats server must look like 127.0.0.1:10085")
    host, _, port_text = server.partition(":")
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ConfigError("stats queries are only allowed against loopback")
    if not port_text.isdigit():
        raise ConfigError("stats server must include a numeric port")
    argv = [
        xray_bin,
        "api",
        "statsquery",
        f"--server={server}",
        "-pattern",
        "user>>>",
    ]
    if reset:
        argv.append("-reset")
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, operator-chosen binary
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise ConfigError(f"xray binary not found: {xray_bin}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ConfigError("statsquery timed out") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip() or "no detail"
        raise ConfigError(f"statsquery failed (exit {completed.returncode}): {detail}")
    text = (completed.stdout or "").strip()
    if not text:
        return {}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"statsquery returned non-JSON: {exc}") from exc
    if not isinstance(payload, (dict, list)):
        raise ConfigError("statsquery JSON must be an object or array")
    return parse_stats_payload(payload)


def format_table(traffic: Mapping[str, UserTraffic]) -> str:
    if not traffic:
        return "(no user traffic counters)\n"
    lines = [f"{'label':<24} {'uplink':>12} {'downlink':>12} {'total':>12}"]
    for label in sorted(traffic):
        row = traffic[label]
        lines.append(f"{row.label:<24} {row.uplink:>12} {row.downlink:>12} {row.total:>12}")
    return "\n".join(lines) + "\n"
