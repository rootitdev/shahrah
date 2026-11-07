from __future__ import annotations

import json
from pathlib import Path

import pytest

from shahrah.models import ConfigError
from shahrah.relay_peers import (
    RelayPeer,
    RelayPeerStore,
    add_peer,
    load_store,
    remove_peer,
    render_peer_configs,
    save_store,
)


def test_peer_collision_detection() -> None:
    store = RelayPeerStore(
        peers=(
            RelayPeer("de", "203.0.113.1", user_port=443, tunnel_port=8443, iran_ip="198.51.100.2"),
        )
    )
    dup_port = RelayPeer(
        "tr", "203.0.113.2", user_port=443, tunnel_port=9453, iran_ip="198.51.100.2"
    )
    with pytest.raises(ConfigError, match="user_port"):
        add_peer(store, dup_port)


def test_render_peer_isolated_configs() -> None:
    peer = RelayPeer("de", "203.0.113.10", user_port=443, tunnel_port=8443, iran_ip="198.51.100.5")
    cfg, core = render_peer_configs(peer, "testpassword123456", "198.51.100.5")
    assert cfg["nodes"]
    assert core["configs"] == ["config.json"]
    peer2 = RelayPeer(
        "tr", "203.0.113.11", user_port=4430, tunnel_port=9453, iran_ip="198.51.100.5"
    )
    cfg2, _ = render_peer_configs(peer2, "otherpassword123456", "198.51.100.5")
    assert cfg2 != cfg


def test_remove_one_peer_leaves_other(tmp_path: Path) -> None:
    path = tmp_path / "peers.json"
    store = add_peer(
        RelayPeerStore(),
        RelayPeer("de", "203.0.113.1", user_port=443, tunnel_port=8443),
    )
    store = add_peer(store, RelayPeer("tr", "203.0.113.2", user_port=4430, tunnel_port=9453))
    save_store(path, store)
    loaded = load_store(path)
    loaded = remove_peer(loaded, "tr")
    save_store(path, loaded)
    data = json.loads(path.read_text())
    assert len(data["peers"]) == 1
    assert data["peers"][0]["name"] == "de"
