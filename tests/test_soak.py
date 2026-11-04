from __future__ import annotations

from typing import ClassVar

import pytest

from shahrah import soak
from shahrah.models import ConfigError
from shahrah.prober import ProbeResult, ProbeTarget


class _FakeSession:
    endpoint_names: ClassVar[list[str]] = ["exit-443"]
    alive = True

    def __init__(self) -> None:
        self.calls = 0

    def probe(self, endpoint_name: str, timeout: float = 8.0, *, target=None) -> ProbeResult:
        self.calls += 1
        return ProbeResult(endpoint_name, True, 12.5)


def test_soak_config_bounds() -> None:
    with pytest.raises(ConfigError, match="30"):
        soak.SoakConfig(duration_s=10)
    with pytest.raises(ConfigError, match="workers"):
        soak.SoakConfig(workers=0)


def test_report_dict_shape() -> None:
    report = soak.SoakReport("exit-443", workers=2, duration_s=60.0, attempts=10, ok=9, fail=1)
    report.latencies_ms = [10.0, 20.0, 30.0]
    report.by_host["telegram.org"] = {"ok": 5, "fail": 0}
    data = report.as_dict()
    assert data["success_rate"] == 0.9
    assert data["endpoint"] == "exit-443"


def test_run_soak_single_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _FakeSession()
    cfg = soak.SoakConfig(workers=1, duration_s=30, interval_s=1.0, timeout_s=2)
    # Enter loop twice then exit (monotonic past stop_at).
    ticks = iter([0.0, 1.0, 1.0, 2.0, 2.0, 40.0, 40.0, 40.0])
    progress: list[dict] = []

    monkeypatch.setattr(soak.time, "monotonic", lambda: next(ticks, 40.0))
    monkeypatch.setattr(soak.time, "sleep", lambda _s: None)
    report = soak.run_soak(
        session,  # type: ignore[arg-type]
        "exit-443",
        [ProbeTarget()],
        cfg,
        on_progress=progress.append,
        progress_every_s=5.0,
    )
    assert session.calls >= 1
    assert report.ok == report.attempts >= 1
    assert report.xray_died is False
    assert progress and "elapsed_s" in progress[-1]


def test_write_progress_file(tmp_path) -> None:
    path = tmp_path / "prog.json"
    soak.write_progress_file(path, {"ok": 1, "attempts": 1})
    assert path.read_text(encoding="utf-8").strip().startswith("{")
