"""Path-health decision engine ("Oracle").

A pure state machine: it receives probe results and the current time, and returns the next
state plus a decision. It performs no I/O, so every behaviour below is unit-testable and
deterministic.

Anti-flapping rules (the reason this exists rather than "pick the fastest"):

* A healthy path only becomes unhealthy after ``fail_streak`` consecutive failures.
* A path that was previously good needs ``recover_streak`` consecutive successes to return.
  A path that has never worked is trusted after a single success so start-up is fast.
* Moving *back* to a better path, or switching on latency alone, requires ``min_dwell_s``
  on the current path. Leaving a failed path is always immediate.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum


class Mode(StrEnum):
    NORMAL = "normal"  # every known path is healthy
    DEGRADED = "degraded"  # some paths are unhealthy, service continues
    RESTRICTED = "restricted"  # only lockdown-capable paths survive: allowlist-like filtering
    OUTAGE = "outage"  # no healthy path for several cycles: enable the crisis tier


@dataclass(frozen=True, slots=True)
class OracleConfig:
    fail_streak: int = 3
    recover_streak: int = 5
    min_dwell_s: float = 120.0
    outage_after_cycles: int = 6
    ewma_alpha: float = 0.3
    latency_switch_ratio: float = 0.6

    def __post_init__(self) -> None:
        if self.fail_streak < 1 or self.recover_streak < 1 or self.outage_after_cycles < 1:
            raise ValueError("streak and cycle thresholds must be >= 1")
        if not 0 < self.ewma_alpha <= 1:
            raise ValueError("ewma_alpha must be in (0, 1]")
        if not 0 < self.latency_switch_ratio < 1:
            raise ValueError("latency_switch_ratio must be in (0, 1)")
        if self.min_dwell_s < 0:
            raise ValueError("min_dwell_s must be >= 0")


@dataclass(frozen=True, slots=True)
class PathSpec:
    """Static description of a path. Lower ``priority`` is preferred."""

    name: str
    priority: int = 0
    lockdown_capable: bool = False


@dataclass(frozen=True, slots=True)
class Probe:
    path: str
    ok: bool
    latency_ms: float | None = None


@dataclass(frozen=True, slots=True)
class PathStats:
    healthy: bool = False
    seen_ok: bool = False
    fail_streak: int = 0
    ok_streak: int = 0
    ewma_ms: float | None = None


@dataclass(frozen=True, slots=True)
class OracleState:
    paths: Mapping[str, PathStats] = field(default_factory=dict)
    active: str | None = None
    active_since: float = 0.0
    down_cycles: int = 0
    mode: Mode = Mode.NORMAL


@dataclass(frozen=True, slots=True)
class Decision:
    state: OracleState
    ranking: tuple[str, ...]  # healthy paths, best first
    switched: bool
    reason: str


def _update_stats(cfg: OracleConfig, prev: PathStats, probe: Probe) -> PathStats:
    if probe.ok:
        ok_streak = prev.ok_streak + 1
        ewma = prev.ewma_ms
        if probe.latency_ms is not None:
            ewma = (
                probe.latency_ms
                if ewma is None
                else cfg.ewma_alpha * probe.latency_ms + (1 - cfg.ewma_alpha) * ewma
            )
        needed = cfg.recover_streak if prev.seen_ok else 1
        healthy = prev.healthy or ok_streak >= needed
        return PathStats(healthy, True, 0, ok_streak, ewma)
    fail_streak = prev.fail_streak + 1
    healthy = prev.healthy and fail_streak < cfg.fail_streak
    return PathStats(healthy, prev.seen_ok, fail_streak, 0, prev.ewma_ms)


def _mode(
    cfg: OracleConfig,
    specs: Mapping[str, PathSpec],
    stats: Mapping[str, PathStats],
    down_cycles: int,
) -> Mode:
    healthy = [name for name in specs if stats.get(name, PathStats()).healthy]
    if not healthy:
        return Mode.OUTAGE if down_cycles >= cfg.outage_after_cycles else Mode.DEGRADED
    unhealthy = [name for name in specs if name not in healthy]
    if not unhealthy:
        return Mode.NORMAL
    # RESTRICTED is a heuristic for allowlist-style filtering: every ordinary path is down
    # while the lockdown-capable ones still work. One failed server must NOT trigger it, so it
    # needs *all* ordinary paths to be down; give it at least two independent ordinary paths
    # to avoid mistaking a single-server outage for censorship.
    ordinary = [name for name in specs if not specs[name].lockdown_capable]
    ordinary_all_down = bool(ordinary) and all(name in unhealthy for name in ordinary)
    if ordinary_all_down and all(specs[name].lockdown_capable for name in healthy):
        return Mode.RESTRICTED
    return Mode.DEGRADED


def step(
    cfg: OracleConfig,
    state: OracleState,
    specs: Sequence[PathSpec],
    probes: Sequence[Probe],
    now: float,
) -> Decision:
    """Advance the engine by one probe cycle."""
    spec_by_name = {spec.name: spec for spec in specs}
    if len(spec_by_name) != len(specs):
        raise ValueError("path names must be unique")

    stats = {name: state.paths.get(name, PathStats()) for name in spec_by_name}
    for probe in probes:
        if probe.path not in spec_by_name:
            raise ValueError(f"probe for unknown path: {probe.path!r}")
        stats[probe.path] = _update_stats(cfg, stats[probe.path], probe)

    def sort_key(name: str) -> tuple[int, float, str]:
        ewma = stats[name].ewma_ms
        return (spec_by_name[name].priority, math.inf if ewma is None else ewma, name)

    ranking = tuple(sorted((n for n in spec_by_name if stats[n].healthy), key=sort_key))
    down_cycles = 0 if ranking else state.down_cycles + 1
    mode = _mode(cfg, spec_by_name, stats, down_cycles)

    active = state.active
    active_since = state.active_since
    switched = False
    reason = "steady"
    best = ranking[0] if ranking else None

    if best is None:
        reason = "no healthy path"
    elif active is None or active not in ranking:
        switched = True
        reason = "initial selection" if active is None else f"{active} unhealthy"
        active, active_since = best, now
    elif best != active and now - state.active_since >= cfg.min_dwell_s:
        better_priority = spec_by_name[best].priority < spec_by_name[active].priority
        best_ewma, active_ewma = stats[best].ewma_ms, stats[active].ewma_ms
        faster = (
            best_ewma is not None
            and active_ewma is not None
            and best_ewma < active_ewma * cfg.latency_switch_ratio
        )
        if better_priority:
            switched, reason = True, f"failback to higher-priority {best}"
        elif faster:
            switched, reason = True, f"{best} is significantly faster"
        if switched:
            active, active_since = best, now

    new_state = replace(
        state,
        paths=stats,
        active=active,
        active_since=active_since,
        down_cycles=down_cycles,
        mode=mode,
    )
    return Decision(state=new_state, ranking=ranking, switched=switched, reason=reason)
