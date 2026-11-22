from __future__ import annotations

import pytest

from shahrah import loadtest
from shahrah.models import ConfigError


def test_connection_bounds() -> None:
    with pytest.raises(ConfigError, match="between"):
        loadtest.run_load(
            "xray",
            __import__("pathlib").Path("."),
            connections=1,
            public_key="A" * 43,
            private_key="A" * 43,
        )


def test_report_dict_shape() -> None:
    report = loadtest.LoadReport(
        connections=10,
        ok=10,
        p50_ms=1.5,
        p95_ms=3.0,
        idle_reaped=True,
        echo_peak=10,
        errors_sample=(),
        duration_s=1.2,
    )
    data = report.as_dict()
    assert data["success_rate"] == 1.0
    assert data["idle_reaped"] is True
