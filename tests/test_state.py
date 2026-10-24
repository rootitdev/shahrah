from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import pytest

from shahrah.models import ConfigError, Profile
from shahrah.state import NodeState, load_state, save_state


@pytest.fixture
def node() -> NodeState:
    return NodeState.create(public_host="vpn.example.org", target_host="www.cloudflare.com")


def test_create_generates_consistent_keys_and_short_id(node: NodeState) -> None:
    assert node.profile is Profile.REALITY_VISION
    other = NodeState.create(public_host="vpn.example.org", target_host="www.cloudflare.com")
    assert node.private_key != other.private_key
    assert node.short_ids != other.short_ids


def test_round_trip_preserves_everything(node: NodeState, tmp_path: Path) -> None:
    node, _ = node.with_user("alice")
    path = tmp_path / "state.json"
    save_state(path, node)
    assert load_state(path) == node


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_state_file_is_owner_only(node: NodeState, tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    save_state(path, node)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_save_leaves_no_temp_files(node: NodeState, tmp_path: Path) -> None:
    save_state(tmp_path / "state.json", node)
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]


def test_user_management(node: NodeState) -> None:
    node, alice = node.with_user("alice")
    node, _ = node.with_user("bob")
    assert node.find_user("alice") == alice
    with pytest.raises(ConfigError, match="already exists"):
        node.with_user("alice")
    node = node.without_user("alice")
    assert [u.label for u in node.users] == ["bob"]
    with pytest.raises(ConfigError, match="no such user"):
        node.without_user("alice")


def test_endpoint_is_public_only(node: NodeState) -> None:
    endpoint = node.endpoint()
    assert endpoint.public_key == node.public_key
    assert node.private_key not in repr(endpoint)


def test_mismatched_public_key_is_rejected(node: NodeState) -> None:
    other = NodeState.create(public_host="vpn.example.org", target_host="www.cloudflare.com")
    data = json.loads(node.to_json())
    data["public_key"] = other.public_key
    with pytest.raises(ConfigError, match="does not match"):
        NodeState.from_json(json.dumps(data))


@pytest.mark.parametrize("text", ["not json", "{}", '{"version": 99}', "[]"])
def test_corrupt_state_fails_loudly(text: str) -> None:
    with pytest.raises(ConfigError):
        NodeState.from_json(text)


def test_hand_edited_invalid_value_is_rejected(node: NodeState) -> None:
    data = json.loads(node.to_json())
    data["port"] = 8443  # not allowed without allow_non_443
    with pytest.raises(ConfigError, match="443"):
        NodeState.from_json(json.dumps(data))


def test_missing_file_has_actionable_message(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="shahrah init"):
        load_state(tmp_path / "missing.json")
