from __future__ import annotations

import json

import pytest

from shahrah import waterwall as ww
from shahrah.models import ConfigError

PW = "p" * 24


def _bh(**kw: object) -> ww.Backhaul:
    base: dict[str, object] = {"iran_ip": "198.51.100.7", "exit_ip": "203.0.113.9", "password": PW}
    return ww.Backhaul(**{**base, **kw})  # type: ignore[arg-type]


def _types(cfg: dict) -> dict[str, str]:
    return {n["name"]: n["type"] for n in cfg["nodes"]}


def _check_chain(cfg: dict) -> None:
    """Every ``next``/``pair``/``destination`` must name an existing node."""
    names = {n["name"] for n in cfg["nodes"]}
    for node in cfg["nodes"]:
        refs = [node.get("next"), node["settings"].get("pair"), node["settings"].get("destination")]
        assert all(r in names for r in refs if r), node


def test_pins() -> None:
    assert all(len(v) == 64 for v in ww.WATERWALL_SHA256.values())
    assert ww.WATERWALL_VERSION.startswith("v")


def test_reverse_mode_chains() -> None:
    b = _bh()
    iran, exit_ = ww.render_iran(b), ww.render_exit(b)
    for cfg in (iran, exit_):
        _check_chain(cfg)
    t = _types(iran)
    assert t["rev-server"] == "ReverseServer" and t["bh-reality-server"] == "RealityServer"
    nodes = {n["name"]: n for n in iran["nodes"]}
    # ReverseServer -> Bridge directly (upstream adjacency rule)
    assert nodes["rev-server"]["next"] == "rev-bridge"
    assert nodes["from-exit"]["settings"]["whitelist"] == ["203.0.113.9/32"]
    assert "whitelist" not in nodes["users"]["settings"]
    enodes = {n["name"]: n for n in exit_["nodes"]}
    assert enodes["rev-bridge"]["next"] == "rev-client"  # Bridge -> ReverseClient directly
    assert enodes["rev-client"]["settings"]["minimum-unused"] == 8
    assert enodes["to-iran"]["settings"]["address"] == "198.51.100.7"
    assert "TcpListener" not in _types(exit_).values()  # exit exposes no port


def test_direct_mode_chains() -> None:
    b = _bh(mode="direct", user_ports=(443, 80))
    iran, exit_ = ww.render_iran(b), ww.render_exit(b)
    _check_chain(iran)
    _check_chain(exit_)
    users = next(n for n in iran["nodes"] if n["name"] == "users")
    assert users["settings"]["port"] == [443, 80]
    lst = next(n for n in exit_["nodes"] if n["name"] == "from-iran")
    assert lst["settings"]["whitelist"] == ["198.51.100.7/32"]


def test_open_peer_when_asked() -> None:
    iran = ww.render_iran(_bh(restrict_peer=False))
    assert all("whitelist" not in n["settings"] for n in iran["nodes"])


@pytest.mark.parametrize(
    "kw",
    [
        {"password": "short"},
        {"password": "x" * 40},
        {"iran_ip": "iran.example.org"},
        {"mode": "mesh"},
        {"tunnel_port": 443},
        {"cover_sni": "192.0.2.1"},
        {"pool": 0},
        {"exit_service": "nope"},
    ],
)
def test_validation(kw: dict[str, object]) -> None:
    with pytest.raises(ConfigError):
        _bh(**kw)


def test_core_json_and_unit() -> None:
    core = ww.core_json("config.json", workers=2)
    assert core["configs"] == ["config.json"] and core["misc"]["workers"] == 2
    assert all(v["loglevel"] == "WARN" for k, v in core["log"].items() if k != "path")
    json.loads(ww.dumps(core))
    assert "-c:/etc/shahrah/waterwall/core.json" in ww.systemd_unit()


def test_cli_renders_both_sides(tmp_path, capsys) -> None:
    from shahrah.cli import main

    key = tmp_path / "bh.key"
    common = ["--iran-ip", "198.51.100.7", "--exit-ip", "203.0.113.9", "--key-file", str(key)]
    assert main(["waterwall-config", "iran", *common, "--out-dir", str(tmp_path / "i")]) == 0
    assert main(["waterwall-config", "exit", *common, "--out-dir", str(tmp_path / "e")]) == 0
    secret = key.read_text().strip()
    assert 16 <= len(secret) <= 32
    for side in ("i", "e"):
        cfg = json.loads((tmp_path / side / "config.json").read_text())
        assert any(n["settings"].get("password") == secret for n in cfg["nodes"])
        assert (tmp_path / side / "core.json").exists()
    assert secret not in capsys.readouterr().out
