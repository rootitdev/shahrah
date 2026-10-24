"""Build client share links and subscription bodies.

Ready-made clients (v2rayNG, Hiddify, Streisand, NekoBox, v2rayN, ...) all import a
base64-encoded list of ``vless://`` links, so the subscription itself is the failover
mechanism for them: unhealthy endpoints are dropped and the rest are ordered best-first.
"""

from __future__ import annotations

import base64
from collections.abc import Iterable, Sequence
from urllib.parse import quote, urlencode

from .models import Endpoint, Profile, User, is_ip
from .xray_config import VISION_FLOW


def _format_host(host: str) -> str:
    # IPv6 literals must be bracketed inside a URL authority.
    return f"[{host}]" if is_ip(host) and ":" in host else host


def vless_link(endpoint: Endpoint, user: User) -> str:
    """Return a ``vless://`` share link for ``user`` on ``endpoint``."""
    query: list[tuple[str, str]] = [
        ("encryption", "none"),
        ("security", "reality"),
        ("sni", endpoint.sni),
        ("fp", endpoint.fingerprint),
        ("pbk", endpoint.public_key),
        ("sid", endpoint.short_id),
    ]
    if endpoint.profile is Profile.REALITY_VISION:
        query += [("type", "tcp"), ("flow", VISION_FLOW), ("headerType", "none")]
    else:
        query += [
            ("type", "xhttp"),
            ("path", endpoint.xhttp_path),
            ("mode", endpoint.xhttp_mode),
        ]
    authority = f"{user.uuid}@{_format_host(endpoint.host)}:{endpoint.port}"
    params = urlencode(query, quote_via=quote)
    return f"vless://{authority}?{params}#{quote(endpoint.name, safe='')}"


def encode_subscription(links: Iterable[str]) -> str:
    """Encode links the way subscription clients expect (base64 of newline-joined text)."""
    body = "\n".join(links) + "\n"
    return base64.b64encode(body.encode("utf-8")).decode("ascii")


def build_subscription(
    endpoints: Sequence[Endpoint],
    user: User,
    healthy_ranking: Sequence[str] | None = None,
) -> str:
    """Build the subscription body for ``user``.

    When ``healthy_ranking`` (best first, from the path-health engine) is given, only those
    endpoints are included, in that order. Without it every endpoint is listed by priority.
    """
    by_name = {endpoint.name: endpoint for endpoint in endpoints}
    if len(by_name) != len(endpoints):
        raise ValueError("endpoint names must be unique")
    if healthy_ranking is None:
        ordered = sorted(endpoints, key=lambda e: (e.priority, e.name))
    else:
        unknown = [name for name in healthy_ranking if name not in by_name]
        if unknown:
            raise ValueError(f"ranking references unknown endpoints: {unknown}")
        ordered = [by_name[name] for name in healthy_ranking]
    return encode_subscription(vless_link(endpoint, user) for endpoint in ordered)
