"""Burn detection: telling "this server is blocked in Iran" apart from "this server is down".

A single vantage point cannot tell the two apart, and the right reaction differs: a down server
is repaired, a *burned* one (its IP or SNI blocked from inside Iran while it works fine
elsewhere) must be rotated out. So the engine compares two vantages:

* **field**   - probes made from inside the censored network.
* **control** - probes made from a free network.

==============  ==============  ==========================================
field           control         verdict
==============  ==============  ==========================================
ok              any             ``HEALTHY``
fail            ok              ``BLOCKED`` (candidate for burn)
fail            fail            ``DOWN`` (a server fault, not censorship)
fail            unknown         ``UNKNOWN`` (never declare a burn blind)
==============  ==============  ==========================================

Like the Oracle this is a pure state machine with no I/O. Two guards keep it from rotating
away healthy infrastructure:

* A burn needs ``burn_after`` consecutive BLOCKED cycles (filters transient loss).
* If *every* endpoint is BLOCKED at once (and there are at least two) that is a network-wide
  event (shutdown, allowlist mode), not a burn: rotating servers would not help. The streaks
  are held and ``network_wide`` is reported instead.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum


class Verdict(StrEnum):
    HEALTHY = "healthy"
    BLOCKED = "blocked"
    DOWN = "down"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class BurnConfig:
    burn_after: int = 5  # consecutive BLOCKED cycles before an endpoint is called burned
    recover_after: int = 10  # consecutive HEALTHY cycles before a burn is forgiven

    def __post_init__(self) -> None:
        if self.burn_after < 1 or self.recover_after < 1:
            raise ValueError("burn_after and recover_after must be >= 1")


@dataclass(frozen=True, slots=True)
class BurnStats:
    blocked_streak: int = 0
    healthy_streak: int = 0
    burned: bool = False


@dataclass(frozen=True, slots=True)
class BurnState:
    paths: Mapping[str, BurnStats] = field(default_factory=dict)

    @property
    def burned(self) -> tuple[str, ...]:
        return tuple(sorted(name for name, stats in self.paths.items() if stats.burned))


@dataclass(frozen=True, slots=True)
class BurnDecision:
    state: BurnState
    verdicts: Mapping[str, Verdict]
    newly_burned: tuple[str, ...]
    recovered: tuple[str, ...]
    network_wide: bool


def classify(field_ok: bool, control_ok: bool | None) -> Verdict:
    if field_ok:
        return Verdict.HEALTHY
    if control_ok is None:
        return Verdict.UNKNOWN
    return Verdict.BLOCKED if control_ok else Verdict.DOWN


def step(
    cfg: BurnConfig,
    state: BurnState,
    field_results: Mapping[str, bool],
    control_results: Mapping[str, bool],
    paths: Iterable[str] | None = None,
) -> BurnDecision:
    """Advance one cycle. ``paths`` defaults to the endpoints seen by the field vantage."""
    names = tuple(paths) if paths is not None else tuple(field_results)
    verdicts = {
        name: classify(field_results[name], control_results.get(name))
        for name in names
        if name in field_results
    }
    blocked = [name for name, v in verdicts.items() if v is Verdict.BLOCKED]
    network_wide = len(verdicts) >= 2 and len(blocked) == len(verdicts)

    new_paths = dict(state.paths)
    newly_burned: list[str] = []
    recovered: list[str] = []
    for name, verdict in verdicts.items():
        prev = state.paths.get(name, BurnStats())
        if verdict is Verdict.BLOCKED and not network_wide:
            streak = prev.blocked_streak + 1
            burned = prev.burned or streak >= cfg.burn_after
            stats = BurnStats(streak, 0, burned)
            if burned and not prev.burned:
                newly_burned.append(name)
        elif verdict is Verdict.HEALTHY:
            healthy = prev.healthy_streak + 1
            forgiven = prev.burned and healthy >= cfg.recover_after
            stats = BurnStats(0, healthy, prev.burned and not forgiven)
            if forgiven:
                recovered.append(name)
        else:
            # DOWN / UNKNOWN / network-wide: no evidence about burning either way. Hold.
            stats = prev
        new_paths[name] = stats

    return BurnDecision(
        state=BurnState(new_paths),
        verdicts=verdicts,
        newly_burned=tuple(sorted(newly_burned)),
        recovered=tuple(sorted(recovered)),
        network_wide=network_wide,
    )
