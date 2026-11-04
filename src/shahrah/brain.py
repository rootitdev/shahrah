"""The brain loop: probe real tunnels -> decide with the Oracle -> steer the panel.

All collaborators are injected, so the loop is fully unit-testable without Xray, a network
or a panel. Failure policy: a failing panel or prober never crashes the loop and never
causes destructive changes; it logs and tries again next cycle.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import burn as burnmod
from .burn import BurnConfig, BurnState
from .models import ConfigError, Endpoint, Profile, User
from .oracle import Decision, Mode, OracleConfig, OracleState, PathSpec, Probe, step
from .panel import PanelError, SyncPlan
from .prober import ProbeError, ProbeResult
from .rotation import serving_ranking

log = logging.getLogger("shahrah.brain")

ProbeRound = Callable[[], Sequence[ProbeResult]]
PanelSync = Callable[[Sequence[str]], SyncPlan]
ControlSource = Callable[[], Mapping[str, bool]]
BurnHook = Callable[[Sequence[str]], None]
ReportSink = Callable[[Sequence[ProbeResult]], None]
Clock = Callable[[], float]
# Called as hook(previous_mode, new_mode) on every mode change; drives the crisis tier.
ModeHook = Callable[[Mode, Mode], None]

CRISIS_MODES = frozenset({Mode.RESTRICTED, Mode.OUTAGE})


@dataclass(frozen=True, slots=True)
class BrainConfig:
    """Public routing data only. Secrets (panel API key) come from the environment."""

    endpoints: tuple[Endpoint, ...]
    probe_user: User
    remarks: Mapping[str, str]  # endpoint name -> panel host remark
    interval_s: float = 30.0
    oracle: OracleConfig = field(default_factory=OracleConfig)
    burn: BurnConfig = field(default_factory=BurnConfig)
    standby: tuple[str, ...] = ()  # spare endpoints, in promotion order (see rotation.py)

    def __post_init__(self) -> None:
        if not self.endpoints:
            raise ConfigError("at least one endpoint is required")
        names = [endpoint.name for endpoint in self.endpoints]
        if len(set(names)) != len(names):
            raise ConfigError("endpoint names must be unique")
        if set(self.standby) - set(names):
            raise ConfigError(
                f"standby refers to unknown endpoints: {sorted(set(self.standby) - set(names))}"
            )
        if len(set(self.standby)) != len(self.standby):
            raise ConfigError("standby endpoints must be unique")
        if len(self.standby) >= len(names):
            raise ConfigError("at least one endpoint must be non-standby")
        unknown = set(self.remarks) - set(names)
        if unknown:
            raise ConfigError(f"remarks refer to unknown endpoints: {sorted(unknown)}")
        if self.interval_s < 5:
            raise ConfigError("interval_s below 5 seconds would hammer the servers")

    def specs(self) -> list[PathSpec]:
        return [
            PathSpec(e.name, priority=e.priority, lockdown_capable=e.lockdown_capable)
            for e in self.endpoints
        ]

    @classmethod
    def from_json(cls, text: str) -> BrainConfig:
        try:
            data = json.loads(text)
            endpoints = tuple(
                Endpoint(**{**item, "profile": Profile(item["profile"])})
                for item in data["endpoints"]
            )
            user = User(data["probe_user"]["uuid"], data["probe_user"]["label"])
            oracle = OracleConfig(**data.get("oracle", {}))
            burn = BurnConfig(**data.get("burn", {}))
            return cls(
                endpoints=endpoints,
                probe_user=user,
                remarks=dict(data.get("remarks", {})),
                interval_s=float(data.get("interval_s", 30.0)),
                oracle=oracle,
                burn=burn,
                standby=tuple(data.get("standby", ())),
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, ConfigError):
                raise
            raise ConfigError(f"brain config is invalid: {exc}") from exc


class Brain:
    def __init__(
        self,
        config: BrainConfig,
        probe_round: ProbeRound,
        panel_sync: PanelSync | None = None,
        *,
        clock: Clock = time.monotonic,
        control_source: ControlSource | None = None,
        on_burn: BurnHook | None = None,
        report_sink: ReportSink | None = None,
        on_mode_change: ModeHook | None = None,
    ) -> None:
        self._config = config
        self._specs = config.specs()
        self._probe_round = probe_round
        self._panel_sync = panel_sync
        self._clock = clock
        self._control_source = control_source
        self._on_burn = on_burn
        self._report_sink = report_sink
        self._on_mode_change = on_mode_change
        self._state = OracleState()
        self._burn_state = BurnState()
        self._promoted: set[str] = set()
        self._synced_ranking: tuple[str, ...] | None = None

    @property
    def state(self) -> OracleState:
        return self._state

    @property
    def burned(self) -> tuple[str, ...]:
        return self._burn_state.burned

    def cycle(self) -> Decision | None:
        """Run one probe -> decide -> sync round. Returns ``None`` if probing itself failed."""
        try:
            results = self._probe_round()
        except ProbeError as exc:
            log.error("probe machinery failed, skipping cycle: %s", exc)
            return None
        probes = [Probe(r.endpoint, r.ok, r.latency_ms) for r in results]
        previous_mode = self._state.mode
        decision = step(self._config.oracle, self._state, self._specs, probes, self._clock())
        self._state = decision.state

        for result in results:
            if not result.ok:
                log.warning("path %s failed: %s", result.endpoint, result.detail)
        if decision.switched:
            log.info("active path -> %s (%s)", decision.state.active, decision.reason)
        if decision.state.mode is not previous_mode:
            log.warning("mode %s -> %s", previous_mode, decision.state.mode)
            self._notify_mode(previous_mode, decision.state.mode)

        self._publish_report(results)
        self._detect_burn(results)
        serving = serving_ranking(decision.ranking, self._config.standby, self._burn_state.burned)
        promoted = {n for n in serving if n in self._config.standby}
        if promoted != self._promoted:
            log.warning("standby endpoints in service: %s", sorted(promoted) or "none")
            self._promoted = promoted
        self._sync_panel(serving)
        return decision

    @property
    def crisis(self) -> bool:
        """True while allowlist-style filtering (restricted) or a full outage is detected."""
        return self._state.mode in CRISIS_MODES

    def _notify_mode(self, previous: Mode, current: Mode) -> None:
        if self._on_mode_change is None:
            return
        try:
            self._on_mode_change(previous, current)
        except Exception:
            # Operator code (e.g. start paqet); the loop must survive it.
            log.exception("mode-change hook failed")

    def _publish_report(self, results: Sequence[ProbeResult]) -> None:
        if self._report_sink is None:
            return
        try:
            self._report_sink(results)
        except OSError as exc:
            log.error("cannot publish vantage report: %s", exc)

    def _detect_burn(self, results: Sequence[ProbeResult]) -> None:
        """Compare this vantage with the control one; hand burned endpoints to the operator."""
        if self._control_source is None:
            return
        outcome = burnmod.step(
            self._config.burn,
            self._burn_state,
            {r.endpoint: r.ok for r in results},
            self._control_source(),
        )
        self._burn_state = outcome.state
        if outcome.network_wide:
            log.warning("every path is blocked from the field but not from control: network-wide")
        for name in outcome.recovered:
            log.info("path %s is reachable again, burn cleared", name)
        if not outcome.newly_burned:
            return
        log.warning(
            "paths burned (blocked in the field, fine from control): %s", outcome.newly_burned
        )
        if self._on_burn is None:
            return
        try:
            self._on_burn(outcome.newly_burned)
        except Exception:
            # The hook is operator code. Whatever it does, the loop must keep running.
            log.exception("on-burn hook failed")

    def _sync_panel(self, ranking: tuple[str, ...]) -> None:
        if self._panel_sync is None or ranking == self._synced_ranking:
            return
        # Only the ranking of mapped paths matters to the panel.
        mapped = tuple(name for name in ranking if name in self._config.remarks)
        try:
            plan = self._panel_sync(mapped)
        except (PanelError, ConfigError) as exc:
            log.error("panel sync failed, will retry next cycle: %s", exc)
            return
        if plan.skipped_reason:
            log.warning("panel untouched: %s", plan.skipped_reason)
            return  # not recorded as synced, so it is retried once paths recover
        self._synced_ranking = ranking
        if not plan.empty:
            log.info(
                "panel updated: enable=%s disable=%s reorder=%s",
                plan.enable,
                plan.disable,
                dict(plan.priorities),
            )


def run_forever(
    brain: Brain,
    interval_s: float,
    *,
    sleep: Callable[[float], None] = time.sleep,
    stop: Callable[[], bool] = lambda: False,
) -> None:
    while not stop():
        started = time.monotonic()
        brain.cycle()
        sleep(max(0.0, interval_s - (time.monotonic() - started)))


def describe(decision: Decision) -> dict[str, Any]:
    """Compact, secret-free summary suitable for logs or a status endpoint."""
    return {
        "mode": str(decision.state.mode),
        "active": decision.state.active,
        "ranking": list(decision.ranking),
        "reason": decision.reason,
    }


__all__ = ["CRISIS_MODES", "Brain", "BrainConfig", "Mode", "ModeHook", "describe", "run_forever"]
