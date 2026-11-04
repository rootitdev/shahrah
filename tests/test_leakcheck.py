from __future__ import annotations

from shahrah import client_template, leakcheck


def test_default_template_passes_leakcheck() -> None:
    report = leakcheck.check_client_template(client_template.xray_client_template())
    assert report.ok, report.as_dict()
    names = {c["name"] for c in report.checks}
    assert "dns_doh_only" in names
    assert "ipv6_blocked" in names
    assert "webrtc_stun_blocked" in names


def test_broken_dns_fails() -> None:
    cfg = client_template.xray_client_template()
    cfg["dns"]["servers"] = ["1.1.1.1"]
    report = leakcheck.check_client_template(cfg)
    assert not report.ok
    assert any(c["name"] == "dns_doh_only" and not c["ok"] for c in report.checks)
