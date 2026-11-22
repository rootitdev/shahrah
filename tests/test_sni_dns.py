from __future__ import annotations

import base64

import pytest

from shahrah import readycheck, sni_dns, sni_scout
from shahrah.models import ConfigError
from shahrah.sni_dns import SniDnsVerdict

NODE = "203.0.113.10"
DNS = {
    "own.example.com": ["203.0.113.10"],
    "neighbour.example.com": ["203.0.113.77"],
    "far.example.com": ["198.51.100.5"],
    "v6.example.com": ["2001:db8:1:2::5"],
    "node.example.com": ["203.0.113.10"],
}


def fake(name: str) -> list[str]:
    return DNS.get(name, [])


@pytest.mark.parametrize(
    ("sni", "verdict"),
    [
        ("own.example.com", SniDnsVerdict.OWN_DOMAIN),
        ("neighbour.example.com", SniDnsVerdict.SAME_PREFIX),
        ("far.example.com", SniDnsVerdict.MISMATCH),
        ("missing.example.com", SniDnsVerdict.UNRESOLVED),
    ],
)
def test_verdicts(sni: str, verdict: SniDnsVerdict) -> None:
    assert sni_dns.check(sni, NODE, fake).verdict is verdict


def test_strict_accepts_only_own_domain() -> None:
    own = sni_dns.check("own.example.com", NODE, fake)
    near = sni_dns.check("neighbour.example.com", NODE, fake)
    assert own.accepted(strict=True) and near.accepted()
    assert not near.accepted(strict=True)
    assert not sni_dns.check("far.example.com", NODE, fake).accepted()


def test_ipv6_prefix_and_bad_input() -> None:
    assert sni_dns.check("v6.example.com", "2001:db8:1:ffff::1", fake).verdict is (
        SniDnsVerdict.SAME_PREFIX
    )
    with pytest.raises(ConfigError):
        sni_dns.check("own.example.com", "not-an-ip", fake)
    assert sni_dns.check("x", NODE, lambda _: ["garbage"]).verdict is SniDnsVerdict.UNRESOLVED


def test_check_many_orders_best_first() -> None:
    names = ["far.example.com", "own.example.com", "neighbour.example.com"]
    got = [c.sni for c in sni_dns.check_many(names, NODE, fake)]
    assert got == ["own.example.com", "neighbour.example.com", "far.example.com"]


def _ok(host: str, port: int, timeout_s: float) -> sni_scout.ScoutResult:
    return sni_scout.ScoutResult(host, True, 10.0, "TLSv1.3", "h2", "ok")


def test_scout_demotes_implausible_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sni_scout, "_handshake", _ok)
    results = sni_scout.scout(
        ["far.example.com", "neighbour.example.com"], node_ip=NODE, resolver=fake
    )
    by_host = {r.host: r for r in results}
    assert by_host["neighbour.example.com"].ok
    assert by_host["neighbour.example.com"].architectures == ("reality",)
    assert not by_host["far.example.com"].ok
    assert "mismatch" in by_host["far.example.com"].detail
    strict = sni_scout.scout(
        ["neighbour.example.com"], node_ip=NODE, resolver=fake, strict_dns=True
    )
    assert not strict[0].ok


def test_scout_without_node_ip_is_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sni_scout, "_handshake", _ok)
    result = sni_scout.scout(["far.example.com"])[0]
    assert result.ok and result.dns is None


def test_readycheck_sni_dns() -> None:
    key = "A" * 43
    links = "\n".join(
        [
            f"vless://u@{NODE}:443?security=reality&sni=far.example.com&pbk={key}&sid=ab#a",
            f"vless://u@node.example.com:443?security=reality&sni=own.example.com&pbk={key}"
            "&sid=ab#b",
            "vless://u@cdn.example.com:443?security=tls&type=xhttp&path=/x#c",
        ]
    )
    body = base64.b64encode(links.encode()).decode()
    checks = readycheck.check_sni_dns(body, fake)
    assert [c.verdict for c in checks] == [SniDnsVerdict.MISMATCH, SniDnsVerdict.OWN_DOMAIN]
