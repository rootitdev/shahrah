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


def test_dns_is_tunnelled_and_cannot_fall_back_to_the_local_resolver() -> None:
    dns = xray_client_template()["dns"]
    assert all(s.startswith("https://") for s in dns["servers"])  # routed, not "https+local"
    assert "localhost" not in json.dumps(dns)
    assert dns["disableFallback"] is True
    assert dns["queryStrategy"] == "UseIPv4"


def test_destinations_are_never_resolved_on_the_device() -> None:
    assert xray_client_template()["routing"]["domainStrategy"] == "AsIs"


def test_ipv6_is_blocked_after_lan_ranges_are_kept_local() -> None:
    rules = xray_client_template()["routing"]["rules"]
    assert rules[0]["outboundTag"] == "DIRECT"
    assert "fe80::/10" in rules[0]["ip"]
    assert rules[1] == {"type": "field", "ip": ["::/0"], "outboundTag": "BLOCK"}


def test_local_proxies_listen_on_loopback_only() -> None:
    inbounds = xray_client_template()["inbounds"]
    assert {i["listen"] for i in inbounds} == {"127.0.0.1"}
    assert [i["port"] for i in inbounds] == [10808, 10809]


def test_the_template_never_defines_a_proxy_outbound_so_the_panel_one_is_first() -> None:
    tags = [o["tag"] for o in xray_client_template()["outbounds"]]
    assert "proxy" not in tags  # PasarGuard prepends its own, which becomes the default route


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
    # Reproduce PasarGuard's merge: proxy outbound(s) first, then the template's own.
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
