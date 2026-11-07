"""Kit-style XHTTP origin must use CDN-safe mode (item 6).

Shahrah CDN listener is the reference; kit templates should not use stream-one/auto
for CDN-facing paths.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from shahrah.models import Listener, Profile, RealityServer, ServerSettings, User
from shahrah.xray_config import render_server_config

KIT_SAMPLE = {
    "tag": "xhttp-bridge",
    "listen": "127.0.0.1",
    "port": 10443,
    "protocol": "vless",
    "settings": {"clients": [{"id": "11111111-1111-4111-8111-111111111111"}], "decryption": "none"},
    "streamSettings": {
        "network": "xhttp",
        "security": "none",
        "xhttpSettings": {"path": "/a1b2c3/v1x2y3", "mode": "packet-up"},
    },
}


def test_kit_sample_uses_packet_up_not_auto() -> None:
    mode = KIT_SAMPLE["streamSettings"]["xhttpSettings"]["mode"]
    assert mode == "packet-up"
    assert mode != "auto"


def test_shahrah_cdn_listener_matches_kit_safe_mode(reality: RealityServer, users: list[User]) -> None:
    server = ServerSettings(
        profile=Profile.REALITY_VISION,
        reality=reality,
        allow_non_443=True,
        extra_listeners=(
            Listener(
                8080,
                Profile.CDN_XHTTP,
                xhttp_path="/a1b2c3/v1x2y3",
                xhttp_mode="packet-up",
                cdn_host="cdn.example.com",
            ),
        ),
    )
    inbounds = render_server_config(server, users)["inbounds"]
    cdn_in = next(i for i in inbounds if i["tag"] == "in-8080")
    assert cdn_in["streamSettings"]["xhttpSettings"]["mode"] == "packet-up"


def test_minimal_xhttp_origin_passes_xray_test(xray_bin: str, tmp_path: Path) -> None:
    """Loopback `xray run -test` for a single XHTTP inbound (no live CDN)."""
    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [KIT_SAMPLE],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }
    path = tmp_path / "xhttp-origin.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    result = subprocess.run(
        [xray_bin, "run", "-test", "-c", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
