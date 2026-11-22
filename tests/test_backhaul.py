"""Backhaul failover store and rendering (no live systemd)."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from shahrah import backhaul, waterwall


@pytest.fixture
def store_path(tmp_path: Path) -> Path:
    key = tmp_path / "backhaul.key"
    key.write_bytes(b"x" * 24)
    store = backhaul.init_store(
        side="iran",
        iran_ip="10.0.0.1",
        exit_ip="10.0.0.2",
        tunnel_port=8443,
        key_file=key,
        workdir=tmp_path / "ww",
        path=tmp_path / "backhaul.json",
        force=True,
    )
    assert store.active == "waterwall-reverse"
    return tmp_path / "backhaul.json"


def test_store_roundtrip(store_path: Path) -> None:
    loaded = backhaul.load_store(store_path)
    assert loaded.waterwall.iran_ip == "10.0.0.1"
    assert loaded.priority[0] == "waterwall-reverse"


def test_render_configs(store_path: Path) -> None:
    store = backhaul.load_store(store_path)
    cfg, core = backhaul.render_waterwall_configs(store, "waterwall-direct")
    assert cfg["name"] == "shahrah-backhaul-iran"
    assert "configs" in core or "configs" in waterwall.dumps(core)


@patch("shahrah.backhaul.path_health", return_value=False)
@patch("shahrah.backhaul.apply_path")
def test_failover_switches_after_streak(
    _apply: object, _health: object, store_path: Path
) -> None:
    store = backhaul.load_store(store_path)
    store = replace(store, control="auto", active="waterwall-reverse")
    note = ""
    for _ in range(3):
        store, note = backhaul.failover_once(store)
    assert "switched" in note or store.active != "waterwall-reverse"
    backhaul.save_store(store, store_path)
    data = json.loads(store_path.read_text(encoding="utf-8"))
    assert data["control"] == "auto"