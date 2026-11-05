"""Cloudflare WARP egress (Google-family) via Xray WireGuard + Hy2 bindDevice."""

from __future__ import annotations

import base64
import os
from dataclasses import replace
from pathlib import Path

import pytest

from shahrah import hysteria2 as hy
from shahrah.cli import main
from shahrah.models import ConfigError, User
from shahrah.state import load_state
from shahrah.warp import (
    hy2_acl_lines,
    hy2_acl_route_all,
    hy2_outbounds,
    parse_wgcf_profile,
    wg_quick_conf,
    xray_outbound,
    xray_routing_rules,
)
from shahrah.xray_config import render_server_config

OBFS = "o" * 24
USER = User("11111111-1111-4111-8111-111111111111", "u-alpha")
DER = b"\x30\x82fake-der-bytes"
PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    + base64.b64encode(DER).decode()
    + "\n-----END CERTIFICATE-----\n"
)


def _keys() -> tuple[str, str]:
    return (
        base64.b64encode(os.urandom(32)).decode(),
        base64.b64encode(os.urandom(32)).decode(),
    )


def _profile_text() -> str:
    priv, pub = _keys()
    return (
        "[Interface]\n"
        f"PrivateKey = {priv}\n"
        "Address = 172.16.0.2/32, 2606:4700:110::1/128\n"
        "DNS = 1.1.1.1\n"
        "\n[Peer]\n"
        f"PublicKey = {pub}\n"
        "Endpoint = engage.cloudflareclient.com:2408\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
    )


def test_parse_wgcf_profile_and_wg_quick() -> None:
    settings = parse_wgcf_profile(_profile_text())
    assert settings.address_v4 == "172.16.0.2/32"
    assert settings.address_v6.startswith("2606:")
    conf = wg_quick_conf(settings)
    assert "Table = off" in conf
    assert settings.private_key in conf


def test_xray_outbound_and_google_routing() -> None:
    settings = parse_wgcf_profile(_profile_text())
    out = xray_outbound(settings)
    assert out["tag"] == "warp" and out["protocol"] == "wireguard"
    domains = xray_routing_rules(settings)[0]["domain"]
    for needle in (
        "domain:google.com",
        "domain:youtube.com",
        "domain:googleapis.com",
        "domain:gstatic.com",
        "domain:googlevideo.com",
    ):
        assert needle in domains
    assert any("play.google.com" in d for d in domains)
    assert any("gemini.google.com" in d for d in domains)
    all_rules = xray_routing_rules(replace(settings, route_all=True))
    assert all_rules[0]["outboundTag"] == "warp" and "network" in all_rules[0]


def test_hy2_acl_ordering() -> None:
    settings = parse_wgcf_profile(_profile_text())
    google = hy2_acl_lines(settings)
    assert any("suffix:google.com" in ln for ln in google)
    assert hy2_acl_route_all(settings) == []
    route_all = replace(settings, route_all=True)
    assert hy2_acl_lines(route_all) == []
    assert hy2_acl_route_all(route_all) == ["    - warp(all)"]
    assert any("bindDevice: warp" in ln for ln in hy2_outbounds(settings))


def test_hy2_render_puts_google_acl_ahead_of_rejects() -> None:
    settings = parse_wgcf_profile(_profile_text())
    text = hy.render_server(
        hy.Hy2Settings(obfs_password=OBFS, pin_sha256="a" * 64, sni="example.com"),
        [USER],
        warp=settings,
    )
    assert "bindDevice: warp" in text
    assert text.index("warp(suffix:google.com)") < text.index("reject(10.0.0.0/8)")
    text_all = hy.render_server(
        hy.Hy2Settings(obfs_password=OBFS, pin_sha256="a" * 64, sni="example.com"),
        [USER],
        warp=replace(settings, route_all=True),
    )
    assert text_all.index("reject(10.0.0.0/8)") < text_all.index("warp(all)")


def test_cli_warp_enable_then_apply(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    state = tmp_path / "state.json"
    profile = tmp_path / "wgcf-profile.conf"
    profile.write_text(_profile_text(), encoding="utf-8")
    cert = tmp_path / "hy2.crt"
    cert.write_text(PEM, encoding="utf-8")

    def run(*args: str) -> int:
        return main(["--state", str(state), *args])

    assert run("init", "--host", "vpn.example.org", "--target", "www.cloudflare.com") == 0
    assert run("user", "add", "alice") == 0
    assert run("warp", "enable", "--profile", str(profile)) == 0
    node = load_state(state)
    assert node.warp is not None
    assert node.warp.address_v4 == "172.16.0.2/32"
    assert not node.warp.route_all

    cfg = render_server_config(node.server_settings(), list(node.users), warp=node.warp)
    tags = [o["tag"] for o in cfg["outbounds"]]
    assert tags[0] == "warp"
    domain_rules = [r for r in cfg["routing"]["rules"] if r.get("outboundTag") == "warp"]
    assert domain_rules and "domain:google.com" in domain_rules[0]["domain"]

    wg = tmp_path / "warp.conf"
    assert run("warp", "wg-conf", "--out", str(wg)) == 0
    assert "Table = off" in wg.read_text(encoding="utf-8")

    assert run("hysteria2", "enable", "--port", "8443", "--cert", str(cert)) == 0
    out = tmp_path / "hy2.yaml"
    assert run("hysteria2", "server", "--out", str(out)) == 0
    body = out.read_text(encoding="utf-8")
    assert "bindDevice: warp" in body and "warp(suffix:youtube.com)" in body

    assert run("warp", "enable", "--profile", str(profile), "--route-all") == 0
    assert load_state(state).warp and load_state(state).warp.route_all  # type: ignore[union-attr]

    assert run("warp", "disable") == 0
    assert load_state(state).warp is None


def test_invalid_profile_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        parse_wgcf_profile("[Interface]\nPrivateKey = nope\n")
