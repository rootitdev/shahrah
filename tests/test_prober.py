from __future__ import annotations

import os
import socket
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

from shahrah.models import Endpoint, Profile, RealityServer, ServerSettings, User
from shahrah.oracle import Probe
from shahrah.prober import (
    ProbeError,
    ProbeResult,
    ProbeTarget,
    XrayProbeSession,
    http_status_via_socks,
    socks5_connect,
)
from shahrah.xray_config import dumps, render_server_config

# --------------------------------------------------------------------------- fake SOCKS5 server


class FakeSocks:
    """Minimal SOCKS5 proxy that answers every CONNECT with a canned HTTP response."""

    def __init__(self, *, reply_code: int = 0, http: bytes = b"HTTP/1.1 204 No Content\r\n\r\n"):
        self.reply_code = reply_code
        self.http = http
        self.requested: list[tuple[str, int]] = []
        self._server = socket.socket()
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(4)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self._server.accept()
        except OSError:
            return
        with conn:
            assert conn.recv(3) == b"\x05\x01\x00"
            conn.sendall(b"\x05\x00")
            header = conn.recv(4)
            assert header == b"\x05\x01\x00\x03"
            length = conn.recv(1)[0]
            host = conn.recv(length).decode()
            port = int.from_bytes(conn.recv(2), "big")
            self.requested.append((host, port))
            conn.sendall(bytes([5, self.reply_code, 0, 1]) + b"\x00" * 6)
            if self.reply_code == 0:
                conn.recv(4096)  # the HTTP request
                conn.sendall(self.http)

    def close(self) -> None:
        self._server.close()


@pytest.fixture
def fake_socks() -> Iterator[FakeSocks]:
    proxy = FakeSocks()
    yield proxy
    proxy.close()


def test_socks_client_sends_domain_not_resolved_ip(fake_socks: FakeSocks) -> None:
    target = ProbeTarget(host="probe.example.com", port=80, path="/x", tls=False)
    assert http_status_via_socks(fake_socks.port, target, timeout=3) == 204
    assert fake_socks.requested == [("probe.example.com", 80)]  # resolved by the server side


def test_socks_connect_failure_code_is_reported() -> None:
    proxy = FakeSocks(reply_code=5)
    try:
        with pytest.raises(ConnectionError, match="code 5"):
            socks5_connect(proxy.port, "probe.example.com", 80, timeout=3)
    finally:
        proxy.close()


def test_malformed_http_is_rejected() -> None:
    proxy = FakeSocks(http=b"garbage\r\n\r\n")
    try:
        target = ProbeTarget(host="probe.example.com", port=80, tls=False)
        with pytest.raises(ConnectionError, match="malformed"):
            http_status_via_socks(proxy.port, target, timeout=3)
    finally:
        proxy.close()


def test_probe_result_maps_to_oracle_probe() -> None:
    result = ProbeResult("exit-1", True, 42.5)
    assert result.to_oracle_probe() == Probe("exit-1", True, 42.5)
    assert ProbeResult("x", False, None, "boom").to_oracle_probe() == Probe("x", False, None)


def test_session_requires_unique_names_and_running_process(
    endpoint: Endpoint, users: list[User]
) -> None:
    with pytest.raises(ValueError, match="unique"):
        XrayProbeSession("xray", [endpoint, endpoint], users[0])
    session = XrayProbeSession("xray", [endpoint], users[0])
    with pytest.raises(ProbeError, match="not running"):
        session.probe(endpoint.name)


def test_session_reports_a_missing_binary(endpoint: Endpoint, users: list[User]) -> None:
    session = XrayProbeSession("definitely-not-a-real-binary", [endpoint], users[0])
    with pytest.raises(FileNotFoundError):
        session.start()
    session.stop()  # must be safe to call after a failed start


# ---------------------------------------------------------------- end-to-end with real Xray

E2E_TARGET = os.environ.get("SHAHRAH_E2E_TARGET", "www.cloudflare.com")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def run_server(
    xray_bin: str, server: ServerSettings, users: list[User], tmp: Path
) -> Iterator[None]:
    config_path = tmp / f"server-{server.port}.json"
    config_path.write_text(dumps(render_server_config(server, users)), encoding="utf-8")
    log = (tmp / f"server-{server.port}.log").open("wb")
    proc = subprocess.Popen(
        [xray_bin, "run", "-c", str(config_path)], stdout=log, stderr=subprocess.STDOUT
    )
    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                socket.create_connection(("127.0.0.1", server.port), timeout=0.3).close()
                break
            except OSError:
                if proc.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError("server xray did not start") from None
                time.sleep(0.1)
        yield
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        log.close()


def _internet_available() -> bool:
    try:
        socket.create_connection(("www.gstatic.com", 443), timeout=3).close()
        socket.create_connection((E2E_TARGET, 443), timeout=3).close()
    except OSError:
        return False
    return True


@pytest.mark.e2e
def test_real_tunnel_probe_end_to_end(
    xray_bin: str, real_keypair: tuple[str, str], tmp_path: Path
) -> None:
    """Server and client Xray on loopback: healthy endpoints pass, broken ones are detected."""
    if not _internet_available():
        pytest.skip("needs internet access (REALITY borrows a real TLS handshake)")
    private, public = real_keypair
    probe_user = User.create("shahrah-probe")
    reality = RealityServer(target_host=E2E_TARGET, private_key=private, short_ids=("ab12",))
    vision_port, xhttp_port, dead_port = _free_port(), _free_port(), _free_port()

    def endpoint(name: str, profile: Profile, port: int, short_id: str = "ab12") -> Endpoint:
        return Endpoint(
            name=name,
            host="127.0.0.1",
            port=port,
            profile=profile,
            public_key=public,
            short_id=short_id,
            sni=E2E_TARGET,
        )

    endpoints = [
        endpoint("vision-ok", Profile.REALITY_VISION, vision_port),
        endpoint("xhttp-ok", Profile.REALITY_XHTTP, xhttp_port),
        endpoint("wrong-short-id", Profile.REALITY_VISION, vision_port, short_id="cd34"),
        endpoint("nothing-listening", Profile.REALITY_VISION, dead_port),
    ]
    vision = ServerSettings(
        profile=Profile.REALITY_VISION,
        reality=reality,
        listen="127.0.0.1",
        port=vision_port,
        allow_non_443=True,
    )
    xhttp = replace(vision, profile=Profile.REALITY_XHTTP, port=xhttp_port)

    with (
        run_server(xray_bin, vision, [probe_user], tmp_path),
        run_server(xray_bin, xhttp, [probe_user], tmp_path),
        XrayProbeSession(xray_bin, endpoints, probe_user) as session,
    ):
        results = {r.endpoint: r for r in session.probe_all(timeout=10)}

    assert results["vision-ok"].ok, results["vision-ok"].detail
    assert results["xhttp-ok"].ok, results["xhttp-ok"].detail
    assert results["vision-ok"].latency_ms is not None
    assert not results["wrong-short-id"].ok
    assert not results["nothing-listening"].ok
