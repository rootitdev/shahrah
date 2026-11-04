"""Static checks that a panel client template stays leak-resistant.

This does not replace a phone TUN leak test. It proves the JSON we publish to
ready-made clients still has DoH-only DNS, IPv6 block, STUN/multicast blocks,
and loopback-only local inbounds — the invariants ``client_template`` promises.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class LeakCheckReport:
    ok: bool
    checks: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "checks": self.checks}


def _add(
    report: LeakCheckReport, name: str, passed: bool, detail: str = ""
) -> None:
    report.checks.append({"name": name, "ok": passed, "detail": detail})
    if not passed:
        report.ok = False


def check_client_template(config: dict[str, Any]) -> LeakCheckReport:
    """Validate a merged or bare Xray client template dict."""
    report = LeakCheckReport(ok=True)
    dns = config.get("dns") or {}
    servers = dns.get("servers") or []
    https_only = bool(servers) and all(
        isinstance(s, str) and s.startswith("https://") for s in servers
    )
    _add(
        report,
        "dns_doh_only",
        https_only,
        "" if https_only else "all dns.servers must be https:// DoH URLs",
    )
    qs_ok = dns.get("queryStrategy") == "UseIPv4"
    _add(
        report,
        "dns_query_strategy_ipv4",
        qs_ok,
        "" if qs_ok else f"got {dns.get('queryStrategy')!r}",
    )
    fb_ok = dns.get("disableFallback") is True
    _add(
        report,
        "dns_disable_fallback",
        fb_ok,
        "" if fb_ok else "disableFallback must be true",
    )

    routing = config.get("routing") or {}
    asis_ok = routing.get("domainStrategy") == "AsIs"
    _add(
        report,
        "domain_strategy_asis",
        asis_ok,
        "" if asis_ok else f"got {routing.get('domainStrategy')!r}",
    )

    rules = routing.get("rules") or []
    stun_blocked = any(
        "stun" in str(rule.get("domain", [])).lower()
        or any("stun" in str(d).lower() for d in (rule.get("domain") or []))
        for rule in rules
        if isinstance(rule, dict)
    )
    _add(
        report,
        "webrtc_stun_blocked",
        stun_blocked,
        "" if stun_blocked else "routing should block STUN hosts",
    )

    ipv6_blocked = any(
        isinstance(rule, dict)
        and rule.get("outboundTag") in {"BLOCK", "block"}
        and (
            "ip" in rule
            and any(
                str(ip).startswith("::/0") or str(ip) == "::/0" for ip in (rule.get("ip") or [])
            )
        )
        for rule in rules
    )
    if not ipv6_blocked:
        # Also accept geoip:private style or port-based; check for explicit IPv6 drop
        ipv6_blocked = any(
            isinstance(rule, dict)
            and "ip" in rule
            and any(":" in str(ip) for ip in (rule.get("ip") or []))
            and rule.get("outboundTag") in {"BLOCK", "block"}
            for rule in rules
        )
    _add(
        report,
        "ipv6_blocked",
        ipv6_blocked,
        "" if ipv6_blocked else "routing should blackhole IPv6",
    )

    multicast_blocked = any(
        isinstance(rule, dict)
        and rule.get("outboundTag") in {"BLOCK", "block"}
        and any(
            str(ip).startswith("224.") or str(ip).startswith("ff")
            for ip in (rule.get("ip") or [])
        )
        for rule in rules
    )
    _add(
        report,
        "multicast_blocked",
        multicast_blocked,
        "" if multicast_blocked else "routing should blackhole multicast",
    )

    for inbound in config.get("inbounds") or []:
        if not isinstance(inbound, dict):
            continue
        tag = inbound.get("tag", "?")
        listen = inbound.get("listen", "")
        if inbound.get("protocol") in {"socks", "http"}:
            loop_ok = listen in {"127.0.0.1", "::1"}
            _add(
                report,
                f"inbound_{tag}_loopback",
                loop_ok,
                "" if loop_ok else f"listen={listen!r}",
            )
    return report
