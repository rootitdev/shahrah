"""One test per lesson from the manual ops scripts (docs/DIAG_LESSONS.md)."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Sequence

from shahrah import nodecheck as nc

DER = b"\x30\x82leaf"
PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    + base64.b64encode(DER).decode()
    + "\n-----END CERTIFICATE-----\n"
)
SS = (
    'tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=10,fd=3))\n'
    'tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=11,fd=6))\n'
    'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=9,fd=13))\n'
)


def test_reality_target_needs_tls13_from_the_node() -> None:
    assert nc.reality_target("t.example", probe=lambda h, p, t: "TLSv1.3").status == "ok"
    assert nc.reality_target("t.example", probe=lambda h, p, t: "TLSv1.2").status == "fail"

    def down(h: str, p: int, t: float) -> str:
        raise OSError("timed out")

    assert nc.reality_target("t.example", probe=down).status == "fail"


def test_pin_must_be_leaf_der_not_spki() -> None:
    leaf = hashlib.sha256(DER).hexdigest()
    assert nc.pin_matches(PEM, leaf).status == "ok"
    colon = ":".join(leaf[i : i + 2] for i in range(0, 64, 2)).upper()
    assert nc.pin_matches(PEM, colon).status == "ok"  # openssl -fingerprint style
    bad = nc.pin_matches(PEM, "0" * 64)
    assert bad.status == "fail" and leaf in bad.detail


def test_stray_listener_on_public_port() -> None:
    check = nc.port_owners(SS, [443, 80], ["xray"])
    assert check.status == "fail" and "80:nginx" in check.detail
    assert nc.port_owners(SS, [443], ["xray"]).status == "ok"


def test_ufw_shadowed_by_custom_nft_table() -> None:
    tables = "table inet filter\ntable inet vpn\n"
    assert nc.firewall_backend(tables, ufw_active=True).status == "warn"
    assert nc.firewall_backend("table inet filter\n", ufw_active=True).status == "ok"
    assert nc.firewall_backend("", ufw_active=False).status == "warn"


def test_public_resolver_is_flagged_loopback_stub_is_fine() -> None:
    assert nc.dns_exposure(SS).status == "ok"
    open_resolver = 'udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("named",pid=5,fd=1))\n'
    assert nc.dns_exposure(open_resolver).status == "fail"
    crisis = 'tcp LISTEN 0 4096 0.0.0.0:53 0.0.0.0:* users:(("xray",pid=10,fd=3))\n'
    assert nc.dns_exposure(crisis).status == "ok"


def test_ipv6_without_route() -> None:
    assert nc.ipv6_sanity("cdn.example", ["2001:db8::1"], False).status == "warn"
    assert nc.ipv6_sanity("cdn.example", [], False).status == "ok"


def test_sysctl_recommendations() -> None:
    good = dict(nc.RECOMMENDED_SYSCTL)
    assert nc.sysctl_values(good).status == "ok"
    assert nc.sysctl_values({**good, "net.ipv4.tcp_mtu_probing": "0"}).status == "warn"


def test_run_all_skips_missing_tools() -> None:
    def no_tools(argv: Sequence[str]) -> str | None:
        return None

    checks = nc.run_all(reality_host=None, public_ports=[443], cmd=no_tools)
    assert {c.name: c.status for c in checks} == {
        "port-owners": "skip",
        "firewall": "skip",
        "sysctl": "skip",
    }


def test_run_all_with_fake_tools() -> None:
    outputs = {"ss": SS, "nft": "table inet filter\n", "ufw": "Status: active\n"}

    def fake(argv: Sequence[str]) -> str | None:
        if argv[0] == "sysctl":
            return nc.RECOMMENDED_SYSCTL[argv[-1]] + "\n"
        return outputs.get(argv[0])

    checks = nc.run_all(
        reality_host="t.example",
        public_ports=[443],
        cmd=fake,
        tls_probe=lambda h, p, t: "TLSv1.3",
    )
    assert all(c.status == "ok" for c in checks), checks
