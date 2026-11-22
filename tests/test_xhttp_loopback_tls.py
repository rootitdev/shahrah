"""XHTTP loopback: configs from shahrah renderers + TLS material (not inline-only)."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import replace
from pathlib import Path

from shahrah.links import vless_link
from shahrah.models import Endpoint, Profile, RealityServer, ServerSettings, User
from shahrah.xray_client import render_probe_config
from shahrah.xray_config import render_server_config

PATH = "/beta-xhttp-path-9f3a2c1"


def _openssl_cert(tmp_path: Path) -> tuple[Path, Path]:
    key = tmp_path / "loopback.key"
    crt = tmp_path / "loopback.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(crt),
            "-days",
            "1",
            "-subj",
            "/CN=cdn.beta.example",
        ],
        check=True,
        capture_output=True,
    )
    return crt, key


def test_rendered_xhttp_tls_server_and_client_pass_xray_test(
    xray_bin: str,
    reality: RealityServer,
    users: list[User],
    tmp_path: Path,
    real_private_key: str,
) -> None:
    crt, key = _openssl_cert(tmp_path)
    server = ServerSettings(
        profile=Profile.REALITY_VISION,
        reality=replace(reality, private_key=real_private_key),
        allow_non_443=True,
        extra_listeners=(),
    )
    srv_cfg = render_server_config(server, users)
    xhttp_in = {
        "tag": "in-xhttp-tls",
        "listen": "127.0.0.1",
        "port": 10443,
        "protocol": "vless",
        "settings": {
            "clients": [{"id": users[0].uuid, "email": users[0].label}],
            "decryption": "none",
        },
        "streamSettings": {
            "network": "xhttp",
            "security": "tls",
            "tlsSettings": {
                "certificates": [
                    {"certificateFile": str(crt), "keyFile": str(key)},
                ],
                "serverName": "cdn.beta.example",
            },
            "xhttpSettings": {"path": PATH, "mode": "packet-up"},
        },
    }
    srv_cfg["inbounds"].append(xhttp_in)

    ep = Endpoint(
        "xhttp-tls",
        "127.0.0.1",
        10443,
        Profile.CDN_XHTTP,
        sni="cdn.beta.example",
        xhttp_path=PATH,
        xhttp_mode="packet-up",
    )
    client = render_probe_config([ep], users[0], [20081])
    der = subprocess.check_output(
        ["openssl", "x509", "-in", str(crt), "-outform", "DER"],
    )
    pin = hashlib.sha256(der).hexdigest()
    for ob in client["outbounds"]:
        tls = ob.get("streamSettings", {}).get("tlsSettings")
        if tls is not None:
            tls["pinnedPeerCertSha256"] = pin

    for name, cfg in (("server", srv_cfg), ("client", client)):
        p = tmp_path / f"{name}.json"
        p.write_text(json.dumps(cfg), encoding="utf-8")
        res = subprocess.run(
            [xray_bin, "run", "-test", "-c", str(p)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0, f"{name}: {res.stdout}{res.stderr}"

    link = vless_link(ep, users[0])
    assert "type=xhttp" in link and "mode=packet-up" in link
    assert "beta-xhttp-path-9f3a2c1" in link
