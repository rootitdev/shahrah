from __future__ import annotations

import base64
from dataclasses import replace
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from shahrah.links import build_subscription, encode_subscription, vless_link
from shahrah.models import Endpoint, Profile, User


def test_vision_link_fields(endpoint: Endpoint, users: list[User]) -> None:
    parts = urlsplit(vless_link(endpoint, users[0]))
    query = {k: v[0] for k, v in parse_qs(parts.query).items()}
    assert parts.scheme == "vless"
    assert parts.username == users[0].uuid
    assert (parts.hostname, parts.port) == ("203.0.113.10", 443)
    assert unquote(parts.fragment) == "exit-1 vision"
    assert query == {
        "encryption": "none",
        "security": "reality",
        "sni": "www.example.com",
        "fp": "chrome",
        "pbk": endpoint.public_key,
        "sid": "0123456789abcdef",
        "type": "tcp",
        "flow": "xtls-rprx-vision",
        "headerType": "none",
    }


def test_xhttp_link_encodes_path(endpoint: Endpoint, users: list[User]) -> None:
    xhttp = replace(endpoint, profile=Profile.REALITY_XHTTP, xhttp_path="/a b/c")
    link = vless_link(xhttp, users[0])
    assert "path=%2Fa%20b%2Fc" in link
    query = {k: v[0] for k, v in parse_qs(urlsplit(link).query).items()}
    assert query["type"] == "xhttp"
    assert query["path"] == "/a b/c"
    assert "flow" not in query


def test_ipv6_host_is_bracketed(endpoint: Endpoint, users: list[User]) -> None:
    link = vless_link(replace(endpoint, host="2001:db8::1"), users[0])
    assert "@[2001:db8::1]:443?" in link
    assert urlsplit(link).hostname == "2001:db8::1"


def test_subscription_roundtrip_and_ordering(endpoint: Endpoint, users: list[User]) -> None:
    second = replace(endpoint, name="exit-2", host="203.0.113.20", priority=1)
    body = build_subscription([second, endpoint], users[0])
    lines = base64.b64decode(body).decode().splitlines()
    assert [unquote(urlsplit(line).fragment) for line in lines] == ["exit-1 vision", "exit-2"]


def test_subscription_follows_health_ranking(endpoint: Endpoint, users: list[User]) -> None:
    second = replace(endpoint, name="exit-2", host="203.0.113.20", priority=1)
    body = build_subscription([endpoint, second], users[0], healthy_ranking=["exit-2"])
    lines = base64.b64decode(body).decode().splitlines()
    assert [unquote(urlsplit(line).fragment) for line in lines] == ["exit-2"]


def test_subscription_rejects_unknown_or_duplicate(endpoint: Endpoint, users: list[User]) -> None:
    with pytest.raises(ValueError, match="unknown"):
        build_subscription([endpoint], users[0], healthy_ranking=["ghost"])
    with pytest.raises(ValueError, match="unique"):
        build_subscription([endpoint, endpoint], users[0])


def test_encode_subscription_is_plain_base64() -> None:
    assert base64.b64decode(encode_subscription(["a", "b"])) == b"a\nb\n"


def test_plain_ws_link_uses_domain_and_host_header() -> None:
    from shahrah.models import Endpoint, Profile, User
    from shahrah.links import vless_link

    ep = Endpoint(
        name="main-ws-80",
        host="static.jetengine.ir",
        port=80,
        profile=Profile.PLAIN_WS,
        sni="static.jetengine.ir",
        tls=False,
        xhttp_path="/shahrah-ws-abc123",
        xhttp_mode="stream-one",
    )
    user = User(label="alice", uuid="11111111-1111-1111-1111-111111111111")
    link = vless_link(ep, user)
    assert "type=ws" in link
    assert "security=none" in link
    assert "static.jetengine.ir:80" in link
    assert "host=static.jetengine.ir" in link
    assert "shahrah-ws-abc123" in link
