"""Loopback smoke test with the real pinned WaterWall binary (SHAHRAH_WW_BIN).

Both "servers" run on 127.0.0.1. The Reality leg performs a real TLS handshake with the cover
site, so this needs internet access.
"""

from __future__ import annotations

import os
import socket
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from shahrah import waterwall as ww

BIN = os.environ.get("SHAHRAH_WW_BIN", "")
pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        not BIN or not Path(BIN).exists(), reason="set SHAHRAH_WW_BIN for the WaterWall smoke"
    ),
]


class _Ok(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:
        body = b"ok-through-backhaul"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _start(tmp: Path, name: str, cfg: dict) -> subprocess.Popen[bytes]:
    d = tmp / name
    d.mkdir()
    (d / "config.json").write_text(ww.dumps(cfg))
    (d / "core.json").write_text(ww.dumps(ww.core_json("config.json", 1, f"{d}/log/")))
    return subprocess.Popen(
        [BIN, "-c:core.json"], cwd=d, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


def _fetch(port: int, attempts: int = 2) -> bytes | None:
    # Each direct-mode connection does a real TLS handshake with the cover site over the
    # internet, so allow one retry for a network hiccup.
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=6) as r:
                return r.read()
        except OSError:
            time.sleep(0.5)
    return None


@pytest.mark.parametrize("mode", ["reverse", "direct"])
def test_backhaul_carries_traffic(tmp_path: Path, mode: str) -> None:
    http = ThreadingHTTPServer(("127.0.0.1", 0), _Ok)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    user_port, tunnel_port = _port(), _port()

    def backhaul(password: str) -> ww.Backhaul:
        return ww.Backhaul(
            iran_ip="127.0.0.1",
            exit_ip="127.0.0.1",
            password=password,
            mode=mode,
            user_ports=(user_port,),
            tunnel_port=tunnel_port,
            exit_service=f"127.0.0.1:{http.server_address[1]}",
            pool=2,
            workers=1,
            listen="127.0.0.1",
        )

    good = backhaul("s" * 24)
    procs = [_start(tmp_path, "iran", ww.render_iran(good))]
    procs.append(_start(tmp_path, "exit", ww.render_exit(good)))
    try:
        time.sleep(3)
        assert [_fetch(user_port) for _ in range(3)] == [b"ok-through-backhaul"] * 3
    finally:
        for p in procs:
            p.terminate()
            p.wait(timeout=5)
    # Mismatched Reality secrets must not carry user traffic.
    procs = [_start(tmp_path, "iran2", ww.render_iran(good))]
    procs.append(_start(tmp_path, "exit2", ww.render_exit(backhaul("w" * 24))))
    try:
        time.sleep(3)
        assert _fetch(user_port) != b"ok-through-backhaul"
    finally:
        for p in procs:
            p.terminate()
            p.wait(timeout=5)
        http.shutdown()
