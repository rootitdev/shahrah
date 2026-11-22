"""Fleet planning (no live panel)."""

from __future__ import annotations

from pathlib import Path

from shahrah.fleet import FleetMember, FleetSpec, plan_member
from shahrah.state import NodeState, save_state


def test_plan_member_includes_client_host(tmp_path: Path) -> None:
    state = NodeState.create(public_host="exit.example.com", target_host="www.cloudflare.com")
    state_path = tmp_path / "state.json"
    save_state(state_path, state)
    member = FleetMember("nl", state_path, "shahrah-nl", "nl", client_host="203.0.113.10")
    block = plan_member(member)
    assert block["hosts"][0]["address"] == ["203.0.113.10"]


def test_fleet_spec_from_json(tmp_path: Path) -> None:
    p = tmp_path / "fleet.json"
    p.write_text(
        '{"exits":[{"slug":"a","state_path":"/etc/shahrah/state.json","core_name":"c","host_prefix":"a"}]}',
        encoding="utf-8",
    )
    spec = FleetSpec.from_path(p)
    assert len(spec.members) == 1