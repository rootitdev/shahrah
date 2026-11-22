from __future__ import annotations

from shahrah.install_flags import ReconfigurePlan, apply_plan
from shahrah.models import Profile
from shahrah.state import NodeState


def test_reconfigure_preserves_keys_and_updates_host() -> None:
    state = NodeState.create(
        public_host="old.example",
        target_host="www.old.com",
        profile=Profile.REALITY_VISION,
        port=443,
    )
    priv = state.private_key
    pub = state.public_key
    plan = ReconfigurePlan(public_host="new.example", target_host="www.cloudflare.com")
    new_state, notes = apply_plan(state, plan)
    assert new_state.private_key == priv
    assert new_state.public_key == pub
    assert new_state.public_host == "new.example"
    assert new_state.target_host == "www.cloudflare.com"
    assert any("public_host" in n for n in notes)
    assert any("target_host" in n for n in notes)


def test_reconfigure_add_multi_port_idempotent() -> None:
    state = NodeState.create(
        public_host="vpn.example.org",
        target_host="www.cloudflare.com",
        profile=Profile.REALITY_VISION,
        port=443,
    )
    state, notes1 = apply_plan(state, ReconfigurePlan(add_multi_port=True))
    assert any("53" in n for n in notes1)
    assert any(listener.port == 53 for listener in state.extra_listeners)
    _, notes2 = apply_plan(state, ReconfigurePlan(add_multi_port=True))
    assert notes2 == ["listener 53 already present (unchanged)"]
