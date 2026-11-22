from __future__ import annotations

import copy
import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from shahrah.client_template import dumps, xray_client_template
from shahrah.models import Endpoint, User
from shahrah.xray_client import render_probe_config


def test_dns_uses_localhost_for_iran_and_doh_elsewhere() -> None:
    dns = xray_client_template()["dns"]
    local = dns["servers"][0]
    assert local["address"] == "localhost"
    assert "geosite:category-ir" in local["domains"]
    assert all(isinstance(s, str) and s.startswith("https://") for s in dns["servers"][1:])
    assert dns["disableFallback"] is True
    assert dns["queryStrategy"] == "UseIPv4"


def test_routing_is_iran_aware() -> None:
    routing = xray_client_template()["routing"]
    assert routing["domainStrategy"] == "IPIfNonMatch"
    rules = routing["rules"]
    ir = next(r for r in rules if "geosite:category-ir" in (r.get("domain") or []))
    assert ir["outboundTag"] == "DIRECT"
    geoip = next(r for r in rules if "geoip:ir" in (r.get("ip") or []))
    assert geoip["outboundTag"] == "DIRECT"


def test_google_ai_domains_use_proxy() -> None:
    rules = xray_client_template()["routing"]["rules"]
    ai = next(r for r in rules if "gemini.google.com" in str(r.get("domain")))
    assert ai["outboundTag"] == "proxy"


def test_ios_template_has_single_socks_inbound() -> None:
    from shahrah.client_template import xray_ios_client_template

    assert len(xray_ios_client_template()["inbounds"]) == 1
    assert xray_ios_client_template()["inbounds"][0]["protocol"] == "socks"


def test_ipv6_is_blocked() -> None:
    rules = xray_client_template()["routing"]["rules"]
    assert any(r.get("ip") == ["::/0"] and r["outboundTag"] == "BLOCK" for r in rules)
    stun = next(r for r in rules if r.get("domain") and any("stun" in d for d in r["domain"]))
    assert stun["outboundTag"] == "BLOCK"


def test_local_proxies_listen_on_loopback_only() -> None:
    inbounds = xray_client_template()["inbounds"]
    assert {i["listen"] for i in inbounds} == {"127.0.0.1"}
    assert [i["port"] for i in inbounds] == [10808, 10809]


def test_the_template_never_defines_a_proxy_outbound_so_the_panel_one_is_first() -> None:
    tags = [o["tag"] for o in xray_client_template()["outbounds"]]
    assert "proxy" not in tags


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"dns_servers": ()}, "at least one"),
        ({"dns_servers": ("1.1.1.1",)}, "https://"),
        ({"dns_servers": ("https+local://1.1.1.1/dns-query",)}, "https://"),
        ({"socks_port": 1080, "http_port": 1080}, "differ"),
    ],
)
def test_invalid_templates_are_rejected(kwargs: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        xray_client_template(**kwargs)  # type: ignore[arg-type]


def test_real_xray_accepts_the_template_merged_like_the_panel_does(
    endpoint: Endpoint,
    users: list[User],
    xray_bin: str,
    real_keypair: tuple[str, str],
    tmp_path: Path,
) -> None:
    proxy = render_probe_config([replace(endpoint, public_key=real_keypair[1])], users[0], [1])[
        "outbounds"
    ][0]
    proxy["tag"] = "proxy"
    merged = copy.deepcopy(xray_client_template())
    merged["outbounds"] = [proxy, *merged["outbounds"]]
    path = tmp_path / "client.json"
    path.write_text(json.dumps(merged), encoding="utf-8")
    result = subprocess.run(
        [xray_bin, "run", "-test", "-c", str(path)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert dumps(xray_client_template()).endswith("\n")
