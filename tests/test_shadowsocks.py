"""Shadowsocks-2022 inbound + share link."""

from __future__ import annotations

import base64
import json

import pytest

from shahrah import shadowsocks as ss
from shahrah.keys import generate_keypair, generate_short_id
from shahrah.models import ConfigError, Profile, RealityServer, ServerSettings, User
from shahrah.xray_config import render_server_config


def _user(label: str = "alice") -> User:
    return User(label=label, uuid="11111111-1111-1111-1111-111111111111")


def test_generate_and_inbound() -> None:
    server_pw = ss.generate_server_password()
    user_pw = ss.generate_user_password()
    settings = ss.Ss2022Settings(
        port=28080, server_password=server_pw, user_passwords={"alice": user_pw}
    )
    inbound = ss.xray_inbound(settings, [_user()])
    assert inbound["protocol"] == "shadowsocks"
    assert inbound["settings"]["method"] == ss.METHOD
    assert inbound["port"] == 28080
    assert inbound["settings"]["clients"][0]["password"] == user_pw


def test_share_link_contains_method() -> None:
    server_pw = base64.b64encode(b"0123456789abcdef").decode()
    user_pw = base64.b64encode(b"fedcba9876543210").decode()
    settings = ss.Ss2022Settings(
        port=28080, server_password=server_pw, user_passwords={"alice": user_pw}
    )
    link = ss.share_link(settings, "exit.example", _user(), "main-ss2022-28080")
    assert link.startswith("ss://")
    assert "exit.example:28080" in link
    assert "main-ss2022-28080" in link


def test_rejects_well_known_ports() -> None:
    pw = base64.b64encode(b"0123456789abcdef").decode()
    with pytest.raises(ConfigError):
        ss.Ss2022Settings(port=443, server_password=pw, user_passwords={"a": pw})


def test_render_includes_ss_inbound() -> None:
    pw = base64.b64encode(b"0123456789abcdef").decode()
    settings = ss.Ss2022Settings(port=28080, server_password=pw, user_passwords={"alice": pw})
    priv, _pub = generate_keypair()
    reality = RealityServer(
        target_host="www.microsoft.com",
        private_key=priv,
        short_ids=(generate_short_id(),),
        server_names=("www.microsoft.com",),
    )
    server = ServerSettings(profile=Profile.REALITY_VISION, reality=reality, port=443)
    rendered = render_server_config(server, [_user()], ss2022=settings)
    cfg = rendered if isinstance(rendered, dict) else json.loads(rendered)
    tags = [i["tag"] for i in cfg["inbounds"]]
    assert any(t.startswith("in-ss2022-") for t in tags)
