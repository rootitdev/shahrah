from __future__ import annotations

import json

import pytest

from shahrah.capacity import plan_for_users
from shahrah.cli import main
from shahrah.models import ConfigError


def test_plan_scales_buffer_down_with_users() -> None:
    small = plan_for_users(200)
    mid = plan_for_users(2000)
    assert small.tuning.buffer_size_kb > mid.tuning.buffer_size_kb
    assert mid.vps_ram_mb >= 2048
    assert mid.xray_rss_mb < mid.vps_ram_mb


def test_plan_rejects_nonsense() -> None:
    with pytest.raises(ConfigError):
        plan_for_users(0)
    with pytest.raises(ConfigError):
        plan_for_users(100_000)


def test_capacity_cli_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["capacity", "--users", "1000", "--json"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["users"] == 1000
    assert "buffer_size_kb" in body["tuning"]
