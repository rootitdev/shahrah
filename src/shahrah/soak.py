"""Sustained Iran-path soak: many workers fetch social/AI URLs through one tunnel for a while.

Unlike ``wave`` (one-shot burst), this keeps an Xray client up and hammers destinations
repeatedly so dead connections, FD leaks, and flaky paths show up over minutes.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import ConfigError
from .prober import ProbeTarget, XrayProbeSession

ProgressFn = Callable[[dict[str, Any]], None]

DEFAULT_SOAK_TARGETS: tuple[ProbeTarget, ...] = (
    ProbeTarget(),
    ProbeTarget("www.instagram.com", path="/", expect_status=frozenset({200, 301, 302})),
    # telegram.org sometimes serves 404 to bare HTTPS probes; still proves the tunnel.
    ProbeTarget("telegram.org", path="/", expect_status=frozenset({200, 301, 302, 404})),
    ProbeTarget("chatgpt.com", path="/", expect_status=frozenset({200, 301, 302, 403})),
    ProbeTarget("claude.ai", path="/", expect_status=frozenset({200, 301, 302, 403})),
)


@dataclass(frozen=True, slots=True)
class SoakConfig:
    workers: int = 50
    duration_s: float = 300.0
    interval_s: float = 2.0
    timeout_s: float = 15.0

    def __post_init__(self) -> None:
        if self.workers < 1 or self.workers > 5000:
            raise ConfigError("soak workers must be between 1 and 5000")
        if self.duration_s < 30:
            raise ConfigError("soak duration must be at least 30 seconds")
        if self.interval_s < 0.2:
            raise ConfigError("soak interval too small")
        if self.timeout_s < 1:
            raise ConfigError("soak timeout must be at least 1 second")


@dataclass
class SoakReport:
    endpoint: str
    workers: int
    duration_s: float
    attempts: int = 0
    ok: int = 0
    fail: int = 0
    by_host: dict[str, dict[str, int]] = field(default_factory=dict)
    latencies_ms: list[float] = field(default_factory=list)
    errors_sample: list[str] = field(default_factory=list)
    xray_died: bool = False

    def as_dict(self) -> dict[str, Any]:
        lats = sorted(self.latencies_ms)
        p50 = lats[len(lats) // 2] if lats else 0.0
        p95 = (
            lats[max(0, int(len(lats) * 0.95) - 1)]
            if len(lats) >= 20
            else (lats[-1] if lats else 0.0)
        )
        rate = (self.ok / self.attempts) if self.attempts else 0.0
        return {
            "endpoint": self.endpoint,
            "workers": self.workers,
            "duration_s": round(self.duration_s, 1),
            "attempts": self.attempts,
            "ok": self.ok,
            "fail": self.fail,
            "success_rate": round(rate, 6),
            "p50_ms": round(p50, 2),
            "p95_ms": round(p95, 2),
            "by_host": self.by_host,
            "errors_sample": self.errors_sample[:12],
            "xray_died": self.xray_died,
        }


def write_progress_file(path: Path, payload: dict[str, Any]) -> None:
    """Atomic-ish progress write so operators can ``tail`` a long soak."""
    text = json.dumps(payload, indent=2) + "\n"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def run_soak(
    session: XrayProbeSession,
    endpoint: str,
    targets: Sequence[ProbeTarget],
    config: SoakConfig,
    *,
    on_progress: ProgressFn | None = None,
    progress_every_s: float = 30.0,
) -> SoakReport:
    """Block until ``duration_s`` elapses; workers share ``session`` safely via probe()."""
    if not targets:
        raise ConfigError("soak needs at least one destination")
    if endpoint not in session.endpoint_names:
        raise ConfigError(f"unknown endpoint {endpoint!r}")
    if progress_every_s < 5.0:
        raise ConfigError("progress_every_s must be at least 5 seconds")

    report = SoakReport(
        endpoint=endpoint,
        workers=config.workers,
        duration_s=config.duration_s,
    )
    lock = threading.Lock()
    stop_at = time.monotonic() + config.duration_s
    started = time.monotonic()
    targets_list = list(targets)
    last_progress = started

    def _maybe_snapshot(*, force: bool = False) -> dict[str, Any] | None:
        nonlocal last_progress
        if on_progress is None:
            return None
        now = time.monotonic()
        if not force and (now - last_progress) < progress_every_s:
            return None
        last_progress = now
        snapshot = report.as_dict()
        snapshot["elapsed_s"] = round(now - started, 1)
        snapshot["remaining_s"] = round(max(0.0, stop_at - now), 1)
        return snapshot

    def worker(worker_id: int) -> None:
        i = worker_id
        while time.monotonic() < stop_at:
            if not session.alive:
                with lock:
                    report.xray_died = True
                return
            dest = targets_list[i % len(targets_list)]
            i += 1
            result = session.probe(endpoint, config.timeout_s, target=dest)
            snapshot: dict[str, Any] | None = None
            with lock:
                report.attempts += 1
                bucket = report.by_host.setdefault(dest.host, {"ok": 0, "fail": 0})
                if result.ok:
                    report.ok += 1
                    bucket["ok"] += 1
                    if result.latency_ms is not None:
                        report.latencies_ms.append(result.latency_ms)
                else:
                    report.fail += 1
                    bucket["fail"] += 1
                    if result.detail and len(report.errors_sample) < 12:
                        sample = f"{dest.host}: {result.detail}"
                        if sample not in report.errors_sample:
                            report.errors_sample.append(sample)
                snapshot = _maybe_snapshot()
            if snapshot is not None and on_progress is not None:
                on_progress(snapshot)
            # Pace workers; remaining time may be less than interval near the end.
            remaining = stop_at - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(config.interval_s, remaining))

    with ThreadPoolExecutor(max_workers=config.workers) as pool:
        futures = [pool.submit(worker, n) for n in range(config.workers)]
        for future in as_completed(futures):
            future.result()
    with lock:
        final = _maybe_snapshot(force=True)
    if final is not None and on_progress is not None:
        on_progress(final)
    return report
