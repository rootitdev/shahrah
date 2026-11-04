from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from shahrah import hysteria2 as hy
from shahrah.cli import main
from shahrah.links import build_subscription
from shahrah.models import ConfigError, User
from shahrah.readycheck import check_subscription
from shahrah.state import load_state

OBFS = "o" * 24
USER = User("11111111-1111-4111-8111-111111111111", "u-alpha")
DER = b"\x30\x82fake-der-bytes"
PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    + base64.b64encode(DER).decode()
    + "\n-----END CERTIFICATE-----\n"
)


def _settings(**kw: object) -> hy.Hy2Settings:
    return hy.Hy2Settings(**{"obfs_password": OBFS, **kw})  # type: ignore[arg-type]


def test_pinned_digests_are_sha256() -> None:
    assert set(hy.HYSTERIA_SHA256) == {"linux-amd64", "linux-arm64"}
    assert all(len(v) == 64 for v in hy.HYSTERIA_SHA256.values())


def test_cert_pin_is_leaf_der_hash_not_spki() -> None:
    assert hy.cert_pin(PEM) == hashlib.sha256(DER).hexdigest()
    with pytest.raises(ConfigError):
        hy.cert_pin("not a pem")


def test_server_config_has_salamander_userpass_and_social_windows() -> None:
    text = hy.render_server(_settings(), [USER])
    assert 'type: "salamander"' in text and f'password: "{OBFS}"' in text
    assert f'"u-alpha": "{USER.uuid}"' in text
    assert "maxStreamReceiveWindow: 4194304" in text  # social preset, not the 8 MiB default
    assert 'listen: ":8443"' in text
    with pytest.raises(ConfigError):
        hy.render_server(_settings(), [])


def test_client_config_declares_moderate_bandwidth_and_keepalive() -> None:
    text = hy.render_client(_settings(pin_sha256="a" * 64), "vpn.example.org", USER)
    assert 'server: "vpn.example.org:8443"' in text
    assert f'auth: "u-alpha:{USER.uuid}"' in text
    assert 'up: "10 mbps"' in text and 'down: "50 mbps"' in text
    assert 'keepAlivePeriod: "10s"' in text and 'pinSHA256: "' + "a" * 64 in text
    bulk = hy.render_client(_settings(tuning="bulk"), "vpn.example.org", USER)
    assert "bandwidth:" not in bulk  # BBR when capacity is unknown
    with pytest.raises(ConfigError):
        hy.render_client(_settings(), "vpn.example.org", USER, socks_listen="0.0.0.0:1080")


def test_port_hopping_link_and_rules() -> None:
    s = _settings(hop=(20000, 40000))
    link = hy.share_link(s, "vpn.example.org", USER, "main-hy2")
    assert "@vpn.example.org:20000-40000/" in link
    client = hy.render_client(s, "vpn.example.org", USER)
    assert "hopInterval" in client
    rules = [" ".join(r) for r in hy.hop_rules(s, "ens3")]
    assert rules == [
        "iptables -t nat -A PREROUTING -i ens3 -p udp --dport 20000:40000 "
        "-j REDIRECT --to-ports 8443"
    ]
    assert hy.hop_rules(_settings()) == []


@pytest.mark.parametrize(
    "kw",
    [
        {"obfs_password": "short"},
        {"pin_sha256": "XYZ"},
        {"hop": (8000, 8900)},  # contains the listen port
        {"hop": (30000, 30010)},  # too narrow
        {"tuning": "gaming"},
        {"sni": "203.0.113.1"},
        {"masquerade_url": "http://x.example.org/"},
    ],
)
def test_settings_validation(kw: dict[str, object]) -> None:
    with pytest.raises(ConfigError):
        _settings(**kw)


def test_share_link_passes_readycheck_and_follows_vless() -> None:
    s = _settings(pin_sha256="b" * 64)
    link = hy.share_link(s, "vpn.example.org", USER, "main-hy2-8443")
    q = parse_qs(urlsplit(link).query)
    assert q["obfs"] == ["salamander"] and q["obfs-password"] == [OBFS]
    assert q["pinSHA256"] == ["b" * 64]
    report = check_subscription(link)
    assert report.ok and report.links[0].profile == "hysteria2"
    weak = link.replace("obfs=salamander", "obfs=none")
    assert not check_subscription(weak).ok


def test_settings_roundtrip() -> None:
    s = _settings(hop=(20000, 40000), pin_sha256="c" * 64)
    assert hy.Hy2Settings.from_dict(json.loads(json.dumps(s.to_dict()))) == s


def test_cli_enable_sub_and_render(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    state = tmp_path / "state.json"
    cert = tmp_path / "hy2.crt"
    cert.write_text(PEM, encoding="utf-8")

    def run(*args: str) -> int:
        return main(["--state", str(state), *args])

    assert run("init", "--host", "vpn.example.org", "--target", "www.cloudflare.com") == 0
    assert run("user", "add", "alice") == 0
    assert run("hysteria2", "enable", "--port", "8443", "--cert", str(cert)) == 0
    node = load_state(state)
    assert node.hysteria2 is not None
    assert node.hysteria2.pin_sha256 == hashlib.sha256(DER).hexdigest()
    secret = node.hysteria2.obfs_password
    assert run("hysteria2", "enable", "--hop", "20000-40000") == 0  # keeps the obfs secret
    assert load_state(state).hysteria2.obfs_password == secret  # type: ignore[union-attr]
    capsys.readouterr()
    assert run("sub", "alice") == 0
    body = base64.b64decode(capsys.readouterr().out.strip()).decode()
    lines = body.strip().splitlines()
    assert lines[0].startswith("vless://") and lines[-1].startswith("hysteria2://")
    assert run("hysteria2", "show") == 0
    assert secret not in capsys.readouterr().out
    out = tmp_path / "server.yaml"
    assert run("hysteria2", "server", "--out", str(out)) == 0
    assert "alice" in out.read_text(encoding="utf-8")
    assert run("hysteria2", "disable") == 0
    assert load_state(state).hysteria2 is None


def test_subscription_keeps_tcp_first(endpoint) -> None:
    body = build_subscription([endpoint], USER, extra_links=["hysteria2://x@h:1/?a=b#n"])
    lines = base64.b64decode(body).decode().splitlines()
    assert lines[0].startswith("vless://") and lines[1].startswith("hysteria2://")


def test_server_rejects_private_and_loopback_egress() -> None:
    """Found in the lab: the Xray exit blocked private ranges but Hysteria2 forwarded to them."""
    from shahrah.xray_config import PRIVATE_NETWORKS

    text = hy.render_server(_settings(), [USER])
    assert "acl:" in text
    for net in PRIVATE_NETWORKS:
        assert f'"reject({net})"' in text


def test_server_egress_matches_xray_freedom_default_block() -> None:
    """Parity with Xray 26 freedom: reserved/TEST-NET/benchmark/multicast are refused too."""
    from shahrah.xray_config import EGRESS_BLOCKED, RESERVED_NETWORKS

    text = hy.render_server(_settings(), [USER])
    for net in ("198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3"):
        assert net in RESERVED_NETWORKS
        assert f'"reject({net})"' in text
    acl = [ln for ln in text.splitlines() if ln.strip().startswith('- "reject(')]
    assert len(acl) == len(EGRESS_BLOCKED)
