"""Validate a ready-made-client subscription body (base64 or plain vless lines).

This is not a phone TUN leak test. It proves the subscription we hand to v2rayNG /
Hiddify / Streisand contains parseable ``vless://`` links with the fields those apps need
for REALITY or CDN-XHTTP.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlparse

from . import sni_bank, sni_dns
from .models import ConfigError, is_ip

_VLESS = re.compile(r"^vless://", re.IGNORECASE)
_HY2 = re.compile(r"^(?:hysteria2|hy2)://", re.IGNORECASE)
_PIN = re.compile(r"^[0-9a-fA-F:]{64,95}$")


@dataclass
class LinkCheck:
    name: str
    ok: bool
    profile: str
    detail: str = ""


@dataclass
class ReadyReport:
    ok: bool
    link_count: int = 0
    links: list[LinkCheck] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "link_count": self.link_count,
            "links": [
                {"name": x.name, "ok": x.ok, "profile": x.profile, "detail": x.detail}
                for x in self.links
            ],
            "notes": self.notes,
        }


def decode_subscription(body: str) -> list[str]:
    """Accept raw newline-separated links or a base64 subscription blob."""
    text = body.strip()
    if not text:
        raise ConfigError("subscription body is empty")
    first = text.splitlines()[0].strip()
    if _VLESS.search(first) or _HY2.search(first):
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    else:
        try:
            # Clients tolerate missing padding.
            pad = "=" * (-len(text) % 4)
            raw = base64.b64decode(text + pad, validate=False)
            decoded = raw.decode("utf-8", errors="replace")
        except (ValueError, UnicodeError) as exc:
            raise ConfigError(f"subscription is not valid base64: {exc}") from exc
        lines = [ln.strip() for ln in decoded.splitlines() if ln.strip()]
    if not lines:
        raise ConfigError("subscription decoded to zero links")
    return lines


def _check_hy2(link: str) -> LinkCheck:
    parsed = urlparse(link)
    name = unquote(parsed.fragment or "") or parsed.hostname or "?"
    qs = {k: (v[0] if v else "") for k, v in parse_qs(parsed.query).items()}
    if not parsed.username or not parsed.hostname:
        return LinkCheck(name, False, "hysteria2", "missing auth or host")
    if qs.get("obfs") != "salamander" or len(qs.get("obfs-password", "")) < 16:
        # Bare QUIC is trivially classified; the product only ships obfuscated links.
        return LinkCheck(name, False, "hysteria2", "salamander obfs missing or weak")
    if qs.get("insecure") == "1" and not qs.get("pinSHA256"):
        return LinkCheck(name, False, "hysteria2", "insecure=1 without pinSHA256")
    pin = qs.get("pinSHA256", "")
    if pin and not _PIN.match(pin):
        return LinkCheck(name, False, "hysteria2", "pinSHA256 is not a 64-hex cert hash")
    return LinkCheck(name, True, "hysteria2", "")


def _check_vless(link: str) -> LinkCheck:
    if _HY2.match(link):
        return _check_hy2(link)
    if not _VLESS.match(link):
        return LinkCheck("?", False, "unknown", "not a vless:// link")
    parsed = urlparse(link)
    fragment = unquote(parsed.fragment or "") or parsed.hostname or "?"
    qs = {k: (v[0] if v else "") for k, v in parse_qs(parsed.query).items()}
    security = qs.get("security", "")
    if security == "reality":
        missing = [k for k in ("pbk", "sid", "sni") if not qs.get(k)]
        if missing:
            return LinkCheck(fragment, False, "reality", f"missing {','.join(missing)}")
        if qs.get("type") == "tcp" and not qs.get("flow"):
            return LinkCheck(fragment, False, "reality-vision", "Vision link missing flow")
        profile = "reality-vision" if qs.get("type") == "tcp" else "reality-xhttp"
        return LinkCheck(fragment, True, profile, "")
    if security in {"none", "tls"}:
        if qs.get("type") != "xhttp":
            return LinkCheck(fragment, False, "cdn", "CDN link must use type=xhttp")
        if not qs.get("path"):
            return LinkCheck(fragment, False, "cdn", "CDN link missing path")
        return LinkCheck(fragment, True, "cdn-xhttp", "")
    return LinkCheck(fragment, False, "unknown", f"unsupported security={security!r}")


def check_subscription(body: str) -> ReadyReport:
    lines = decode_subscription(body)
    report = ReadyReport(ok=True, link_count=len(lines))
    for line in lines:
        item = _check_vless(line)
        report.links.append(item)
        if not item.ok:
            report.ok = False
    report.notes.append(
        "Import in TUN/VPN mode on the device; proxy-only cannot block WebRTC leaks."
    )
    report.notes.append("Run shahrah leakcheck on the panel client template separately.")
    if report.link_count < 1:
        report.ok = False
    return report


def check_sni_dns(
    body: str,
    resolver: sni_dns.Resolver = sni_dns.system_resolver,
) -> list[sni_dns.SniDnsCheck]:
    """SNI<->DNS plausibility for every REALITY link whose address is a literal IP.

    Links addressed by a domain are resolved first; the check then runs against each address.
    """
    checks: list[sni_dns.SniDnsCheck] = []
    for link in decode_subscription(body):
        if not _VLESS.match(link):
            continue
        parsed = urlparse(link)
        qs = {k: (v[0] if v else "") for k, v in parse_qs(parsed.query).items()}
        if qs.get("security") != "reality" or not qs.get("sni") or not parsed.hostname:
            continue
        host = parsed.hostname
        addresses = [host] if is_ip(host) else list(resolver(host))
        checks.extend(sni_dns.check(qs["sni"], ip, resolver) for ip in addresses)
    return checks


def link_snis(body: str) -> list[str]:
    """SNIs of every REALITY link in a subscription body (order kept, no duplicates)."""
    seen: list[str] = []
    for link in decode_subscription(body):
        if not _VLESS.match(link):
            continue
        qs = {k: (v[0] if v else "") for k, v in parse_qs(urlparse(link).query).items()}
        sni = qs.get("sni", "")
        if qs.get("security") == "reality" and sni and sni not in seen:
            seen.append(sni)
    return seen


def check_sni_bank(body: str, bank: sni_bank.SniBank, now: float) -> list[tuple[str, str]]:
    """Problems with the SNIs a subscription ships, judged by the SNI bank: (sni, problem).

    Flags names the bank does not know, names whose verification expired (field reports: some
    die in under 24 h) and names that scored below the pick threshold (e.g. a block sighting).
    """
    problems: list[tuple[str, str]] = []
    for sni in link_snis(body):
        cand = bank.get(sni)
        if cand is None:
            problems.append((sni, "not in the SNI bank (unverified)"))
            continue
        sc = sni_bank.score(cand, now)
        if sc.expired:
            problems.append((sni, "verification expired: run `shahrah sni-bank refresh`"))
        elif not sc.usable:
            problems.append((sni, f"score {sc.total}: {'; '.join(sc.reasons)}"))
    return problems
