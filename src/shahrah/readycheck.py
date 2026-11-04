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

from .models import ConfigError

_VLESS = re.compile(r"^vless://", re.IGNORECASE)


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
    if _VLESS.search(text.splitlines()[0].strip()):
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


def _check_vless(link: str) -> LinkCheck:
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
