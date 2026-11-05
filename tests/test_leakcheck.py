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

def test_server_config_rejects_warp_as_default() -> None:
    bad = {"outbounds": [{"tag": "warp"}, {"tag": "direct"}], "routing": {"rules": []}}
    rep = leakcheck.check_server_config(bad)
    assert not rep.ok
    names = {c["name"]: c["ok"] for c in rep.checks}
    assert names["default_outbound_not_warp"] is False

    good = {
        "outbounds": [{"tag": "direct"}, {"tag": "block"}, {"tag": "warp"}],
        "routing": {"rules": [{"type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "block"}]},
    }
    rep2 = leakcheck.check_server_config(good)
    assert rep2.ok
