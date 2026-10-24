"""Turn a Shahrah node description into the objects a PasarGuard panel needs.

In panel-managed mode PasarGuard owns users, quotas and the running Xray; Shahrah only has to
tell it *what to run* (a core config) and *what clients should connect to* (hosts). Both are
derived from the same :class:`NodeState`, so the server and the subscription cannot drift.

Everything here is pure (no I/O); :meth:`PanelClient.ensure_core` / ``ensure_host`` apply it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import Endpoint, Profile
from .state import NodeState
from .xray_config import inbound_tag, render_server_config

CORE_TYPE = "xray"


@dataclass(frozen=True, slots=True)
class HostPlan:
    """One panel host and the Shahrah endpoint it mirrors."""

    endpoint: str  # Shahrah path name (what the brain steers)
    remark: str  # panel host remark (unique key on the panel side)
    payload: dict[str, Any]


def core_config(state: NodeState) -> dict[str, Any]:
    """Xray config for a panel core: the node's inbounds with no clients (the panel adds them).

    The panel node runs its own stats/API plumbing, so the loopback stats API is not included.
    """
    return render_server_config(state.server_settings(), users=())


def core_payload(name: str, state: NodeState) -> dict[str, Any]:
    """``POST /api/core`` body."""
    return {
        "name": name,
        "type": CORE_TYPE,
        "config": core_config(state),
        "exclude_inbound_tags": [],
        "fallbacks_inbound_tags": [],
    }


def _host_payload(endpoint: Endpoint, tag: str, remark: str) -> dict[str, Any]:
    cdn = endpoint.profile is Profile.CDN_XHTTP
    payload: dict[str, Any] = {
        "remark": remark,
        "address": [endpoint.host],
        "inbound_tag": tag,
        "port": endpoint.port,
        "priority": endpoint.priority,
        "is_disabled": False,
        "fingerprint": endpoint.fingerprint,
    }
    if cdn:
        # TLS is terminated by the CDN edge, so the host overrides the plain inbound.
        payload["security"] = "tls" if endpoint.tls else "none"
        if endpoint.tls:
            payload["sni"] = [endpoint.sni]
            payload["alpn"] = ["h2", "http/1.1"]
        else:
            payload["fingerprint"] = ""  # no TLS, so no TLS fingerprint
        payload["host"] = [endpoint.host]
    else:
        payload["security"] = "inbound_default"
        payload["sni"] = [endpoint.sni]
    if endpoint.profile in (Profile.REALITY_XHTTP, Profile.CDN_XHTTP):
        payload["path"] = endpoint.xhttp_path
        payload["transport_settings"] = {"xhttp_settings": {"mode": endpoint.xhttp_mode}}
    return payload


def host_plans(state: NodeState, *, prefix: str = "main") -> list[HostPlan]:
    """One panel host per listener, in listener order (matches the inbound tags)."""
    endpoints = state.endpoints(prefix)
    listeners = state.server_settings().listeners()
    return [
        HostPlan(
            endpoint.name,
            endpoint.name,
            _host_payload(endpoint, inbound_tag(index, listener), endpoint.name),
        )
        for index, (endpoint, listener) in enumerate(zip(endpoints, listeners, strict=True))
    ]


def remarks(plans: list[HostPlan]) -> dict[str, str]:
    """``endpoint -> panel remark`` mapping for the brain config."""
    return {plan.endpoint: plan.remark for plan in plans}
