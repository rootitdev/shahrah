from __future__ import annotations

import base64

from shahrah.links import build_subscription, vless_link
from shahrah.models import Endpoint, Profile, User
from shahrah.readycheck import check_subscription, decode_subscription


def _reality() -> Endpoint:
    return Endpoint(
        name="exit-443",
        host="203.0.113.10",
        port=443,
        profile=Profile.REALITY_VISION,
        sni="www.cloudflare.com",
        public_key="A" * 43,
        short_id="0123456789abcdef",
        fingerprint="chrome",
        priority=10,
    )


def test_decodes_plain_and_base64() -> None:
    user = User(label="u", uuid="00000000-0000-4000-8000-000000000001")
    link = vless_link(_reality(), user)
    assert decode_subscription(link) == [link]
    blob = base64.b64encode(link.encode()).decode()
    assert decode_subscription(blob) == [link]


def test_subscription_passes() -> None:
    user = User(label="u", uuid="00000000-0000-4000-8000-000000000001")
    body = build_subscription([_reality()], user)
    report = check_subscription(body)
    assert report.ok
    assert report.link_count == 1
    assert report.links[0].profile == "reality-vision"


def test_broken_link_fails() -> None:
    report = check_subscription("vless://x@host:443?security=reality&type=tcp#bad")
    assert not report.ok
