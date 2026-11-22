"""Loopback smoke test with the real pinned Hysteria binary.

Set SHAHRAH_HY2_BIN to the downloaded ``hysteria`` binary; needs ``openssl`` for a throwaway
self-signed certificate. Traffic goes client SOCKS -> QUIC+salamander -> server -> a local
HTTP server, so no internet access is required.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from shahrah import hysteria2 as hy
from shahrah.models import User
from shahrah.prober import ProbeTarget, probe_socks

BIN = os.environ.get("SHAHRAH_HY2_BIN", "")
pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        not BIN or not Path(BIN).exists() or shutil.which("openssl") is None,
        reason="set SHAHRAH_HY2_BIN (and install openssl) to run the hysteria2 smoke test",
    ),
]


class _Ok(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:
        body = b"x" * 200_000  # one feed image worth of bytes
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _free_udp() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_loopback_traffic_through_salamander(tmp_path: Path) -> None:
    crt, key = tmp_path / "hy2.crt", tmp_path / "hy2.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=hy2.example.org",
            "-addext",
            "subjectAltName=DNS:hy2.example.org",
            "-keyout",
            str(key),
            "-out",
            str(crt),
        ],
        check=True,
        capture_output=True,
    )
    port = _free_udp()
    settings = hy.Hy2Settings(
        port=port,
        obfs_password=hy.generate_secret(),
        sni="hy2.example.org",
        pin_sha256=hy.cert_pin(crt.read_text()),
        cert_path=str(crt),
        key_path=str(key),
    )
    user = User.create("smoke")
    server_cfg = tmp_path / "server.yaml"
    server_cfg.write_text(hy.render_server(settings, [user], listen_host="127.0.0.1"))
    http = ThreadingHTTPServer(("127.0.0.1", 0), _Ok)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    server = subprocess.Popen(
        [BIN, "server", "-c", str(server_cfg), "--disable-update-check"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(1.0)
        assert server.poll() is None, "hysteria server exited"
        target = ProbeTarget(
            host="127.0.0.1",
            port=http.server_address[1],
            path="/",
            tls=False,
            expect_status=frozenset({200}),
        )
        with hy.Hy2ProbeSession(BIN, settings, "127.0.0.1", user) as session:
            results = [probe_socks("hy2", session.socks_port, target) for _ in range(5)]
        assert all(r.ok for r in results), [r.detail for r in results]
        # A wrong obfs password must fail: salamander is the gate, not a cosmetic option.
        bad = hy.Hy2Settings(**{**settings.to_dict(), "hop": None, "obfs_password": "w" * 24})
        with hy.Hy2ProbeSession(BIN, bad, "127.0.0.1", user) as session:
            assert not probe_socks("hy2", session.socks_port, target, timeout=4).ok
        # A wrong certificate pin must fail too (insecure=true is only safe with the pin).
        wrong_pin = hy.Hy2Settings(**{**settings.to_dict(), "hop": None, "pin_sha256": "0" * 64})
        with hy.Hy2ProbeSession(BIN, wrong_pin, "127.0.0.1", user) as session:
            assert not probe_socks("hy2", session.socks_port, target, timeout=4).ok
    finally:
        server.terminate()
        server.wait(timeout=5)
        http.shutdown()
