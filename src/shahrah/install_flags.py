"""Apply explicit installer flags onto an existing NodeState without rotating keys."""

from __future__ import annotations

from dataclasses import dataclass

from .state import NodeState


@dataclass(frozen=True, slots=True)
class ReconfigurePlan:
    """Only fields the installer explicitly passed are non-None / set."""

    public_host: str | None = None
    target_host: str | None = None
    add_multi_port: bool = False  # add 53:reality-xhttp if missing


def apply_plan(state: NodeState, plan: ReconfigurePlan) -> tuple[NodeState, list[str]]:
    """Return updated state and human-readable change log (no secrets)."""
    notes: list[str] = []
    out = state
    if plan.public_host is not None and plan.public_host != state.public_host:
        out = out.with_public_host(plan.public_host)
        notes.append(f"public_host -> {plan.public_host!r}")
    if plan.target_host is not None and plan.target_host != state.target_host:
        out = out.with_target(plan.target_host)
        notes.append(f"target_host -> {plan.target_host!r}")
    if plan.add_multi_port:
        ports = {listener.port for listener in out.extra_listeners}
        if 53 not in ports:
            from .models import Listener, Profile

            out = out.with_listener(Listener(53, Profile.REALITY_XHTTP))
            notes.append("extra listener 53:reality-xhttp added")
        else:
            notes.append("listener 53 already present (unchanged)")
    return out, notes
