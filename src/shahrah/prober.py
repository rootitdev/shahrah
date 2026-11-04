"""Real tunnel prober.

An edge answering TLS does not mean the tunnel works (a REALITY server can accept the TCP
connection yet reject your short id, or its exit can be cut off). This prober sends an actual
HTTP request *through* each endpoint with a real Xray client and reports whether it came back,
which is the signal the Oracle needs.

The SOCKS5 client is intentionally tiny and standard-library only. The destination is
resolved on the server side (SOCKS5 domain addressing), so probing never leaks DNS locally.
"""

from __future__ import annotations

import socket
import ssl
import subprocess
import tempfile
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType

from .models import Endpoint, User
from .oracle import Probe
from .xray_client import LOOPBACK, render_probe_config
from .xray_config import dumps

# A browser-like User-Agent: some CDNs/WAFs answer odd UAs with 403/challenge pages, which
# made health checks report healthy paths as down (docs/DIAG_LESSONS.md).
PROBE_USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0 Mobile Safari/537.36"
)


class ProbeError(RuntimeError):
    """The probe machinery itself failed (not the endpoint under test)."""


@dataclass(frozen=True, slots=True)
class ProbeTarget:
    """What to fetch through the tunnel. Keep it a stable, boring, always-up URL."""

    host: str = "www.gstatic.com"
    port: int = 443
    path: str = "/generate_204"
    tls: bool = True
    expect_status: frozenset[int] = field(default_factory=lambda: frozenset({204}))


@dataclass(frozen=True, slots=True)
class ProbeResult:
    endpoint: str
    ok: bool
    latency_ms: float | None
    detail: str = ""

    def to_oracle_probe(self) -> Probe:
        return Probe(path=self.endpoint, ok=self.ok, latency_ms=self.latency_ms)


# Reachability through the tunnel: any HTTP answer proves the path; a censored path fails at
# TCP/TLS level instead. Front pages may redirect, 4xx is fine for bare CDN hosts.
ANY_HTTP = frozenset(range(200, 500))


@dataclass(frozen=True, slots=True)
class WeightedTarget:
    target: ProbeTarget
    weight: float = 1.0

    def __post_init__(self) -> None:
        if self.weight <= 0:
            raise ValueError("weight must be positive")


# Instagram-first quality probe (project goal: social apps over bulk speed). The app talks to
# its API host and fetches media from the cdninstagram CDN; www is the web front. A generic
# 204 target keeps one non-Meta signal so a Meta-side incident is not read as a dead path.
INSTAGRAM_TARGETS: tuple[WeightedTarget, ...] = (
    WeightedTarget(ProbeTarget("i.instagram.com", path="/", expect_status=ANY_HTTP), 3.0),
    WeightedTarget(ProbeTarget("static.cdninstagram.com", path="/", expect_status=ANY_HTTP), 2.0),
    WeightedTarget(ProbeTarget("www.instagram.com", path="/", expect_status=ANY_HTTP), 2.0),
    WeightedTarget(ProbeTarget(), 1.0),
)


def social_quality(
    name: str,
    results: Sequence[tuple[float, ProbeResult]],
    *,
    min_score: float = 0.75,
) -> ProbeResult:
    """Fold weighted per-target results into one Oracle-ready result for path ``name``.

    ``ok`` when the weighted success share reaches ``min_score``; latency is the weighted mean
    over successful targets, so a path that is slow on Instagram ranks behind a snappier one.
    """
    if not results:
        raise ValueError("no results to aggregate")
    if not 0 < min_score <= 1:
        raise ValueError("min_score must be in (0, 1]")
    total = sum(weight for weight, _ in results)
    good = [(w, r) for w, r in results if r.ok and r.latency_ms is not None]
    score = sum(w for w, _ in good) / total
    if score + 1e-9 < min_score or not good:
        failed = ",".join(r.detail or "fail" for _, r in results if not r.ok)[:120]
        return ProbeResult(name, False, None, f"social score {score:.2f}: {failed}")
    latency = sum(w * (r.latency_ms or 0.0) for w, r in good) / sum(w for w, _ in good)
    return ProbeResult(name, True, round(latency, 1), f"social score {score:.2f}")


def probe_weighted(
    name: str,
    probe: Callable[[ProbeTarget], ProbeResult],
    targets: Sequence[WeightedTarget] = INSTAGRAM_TARGETS,
    *,
    min_score: float = 0.75,
) -> ProbeResult:
    """Run ``probe`` against every target and aggregate with :func:`social_quality`."""
    return social_quality(name, [(t.weight, probe(t.target)) for t in targets], min_score=min_score)


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("connection closed during SOCKS5 handshake")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def socks5_connect(proxy_port: int, host: str, port: int, timeout: float) -> socket.socket:
    """Open a TCP stream to ``host:port`` through a local SOCKS5 proxy (no auth)."""
    sock = socket.create_connection((LOOPBACK, proxy_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            raise ConnectionError("SOCKS5 proxy refused no-auth negotiation")
        name = host.encode("idna")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big"))
        _, reply, _, atyp = _recv_exact(sock, 4)
        if reply != 0:
            raise ConnectionError(f"SOCKS5 connect failed with code {reply}")
        if atyp == 1:
            _recv_exact(sock, 4 + 2)
        elif atyp == 4:
            _recv_exact(sock, 16 + 2)
        elif atyp == 3:
            _recv_exact(sock, _recv_exact(sock, 1)[0] + 2)
        else:
            raise ConnectionError(f"SOCKS5 reply has unknown address type {atyp}")
    except BaseException:
        sock.close()
        raise
    return sock


def http_status_via_socks(proxy_port: int, target: ProbeTarget, timeout: float) -> int:
    """GET ``target`` through the proxy and return the HTTP status code."""
    sock = socks5_connect(proxy_port, target.host, target.port, timeout)
    try:
        stream: socket.socket | ssl.SSLSocket = sock
        if target.tls:
            context = ssl.create_default_context()
            stream = context.wrap_socket(sock, server_hostname=target.host)
        request = (
            f"GET {target.path} HTTP/1.1\r\nHost: {target.host}\r\n"
            f"User-Agent: {PROBE_USER_AGENT}\r\nConnection: close\r\n\r\n"
        )
        stream.sendall(request.encode("ascii"))
        buffer = b""
        while b"\r\n" not in buffer:
            chunk = stream.recv(1024)
            if not chunk:
                break
            buffer += chunk
        parts = buffer.split(b"\r\n", 1)[0].split()
        if len(parts) < 2 or not parts[0].startswith(b"HTTP/") or not parts[1].isdigit():
            raise ConnectionError("malformed HTTP response through tunnel")
        return int(parts[1])
    finally:
        sock.close()


def probe_socks(
    name: str,
    socks_port: int,
    target: ProbeTarget | None = None,
    timeout: float = 8.0,
) -> ProbeResult:
    """Probe a path exposed as a loopback SOCKS5 proxy by another data plane (e.g. the paqet
    client). Same semantics as :meth:`XrayProbeSession.probe`; never raises for path failures.
    """
    dest = target or ProbeTarget()
    started = time.monotonic()
    try:
        status = http_status_via_socks(socks_port, dest, timeout)
    except (OSError, ConnectionError, ssl.SSLError, UnicodeError) as exc:
        return ProbeResult(name, False, None, f"{type(exc).__name__}: {exc}"[:160])
    elapsed = (time.monotonic() - started) * 1000
    if status in dest.expect_status:
        return ProbeResult(name, True, round(elapsed, 1))
    return ProbeResult(name, False, None, f"unexpected HTTP status {status}")


def _free_ports(count: int) -> list[int]:
    sockets = [socket.socket() for _ in range(count)]
    try:
        for sock in sockets:
            sock.bind((LOOPBACK, 0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


class XrayProbeSession:
    """Owns one Xray client process that exposes every endpoint as a local SOCKS port."""

    def __init__(
        self,
        xray_bin: str,
        endpoints: Sequence[Endpoint],
        probe_user: User,
        *,
        target: ProbeTarget | None = None,
        startup_timeout: float = 10.0,
    ) -> None:
        names = [endpoint.name for endpoint in endpoints]
        if len(set(names)) != len(names):
            raise ValueError("endpoint names must be unique")
        self._xray_bin = xray_bin
        self._endpoints = list(endpoints)
        self._user = probe_user
        self._target = target or ProbeTarget()
        self._startup_timeout = startup_timeout
        self._ports: dict[str, int] = {}
        self._proc: subprocess.Popen[bytes] | None = None
        self._tmp: tempfile.TemporaryDirectory[str] | None = None

    def __enter__(self) -> XrayProbeSession:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()

    def start(self) -> None:
        if self._proc is not None:
            raise ProbeError("probe session already started")
        ports = _free_ports(len(self._endpoints))
        self._ports = {ep.name: port for ep, port in zip(self._endpoints, ports, strict=True)}
        self._tmp = tempfile.TemporaryDirectory(prefix="shahrah-probe-")
        tmp = Path(self._tmp.name)
        config_path = tmp / "client.json"
        config_path.write_text(
            dumps(render_probe_config(self._endpoints, self._user, ports)), encoding="utf-8"
        )
        log_path = tmp / "xray.log"
        with log_path.open("wb") as log:
            self._proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                [self._xray_bin, "run", "-c", str(config_path)],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        try:
            self._wait_ready(ports, log_path)
        except BaseException:
            self.stop()
            raise

    def _wait_ready(self, ports: Sequence[int], log_path: Path) -> None:
        if self._proc is None:
            raise ProbeError("probe session is not running")
        deadline = time.monotonic() + self._startup_timeout
        pending = set(ports)
        while pending:
            if self._proc.poll() is not None:
                tail = log_path.read_text(errors="replace")[-600:]
                raise ProbeError(f"xray exited during start-up: {tail.strip()}")
            for port in list(pending):
                try:
                    socket.create_connection((LOOPBACK, port), timeout=0.3).close()
                except OSError:
                    continue
                pending.discard(port)
            if pending and time.monotonic() > deadline:
                raise ProbeError("xray did not open its probe ports in time")
            if pending:
                time.sleep(0.1)

    def stop(self) -> None:
        proc, self._proc = self._proc, None
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp = None

    def socks_port(self, endpoint_name: str) -> int:
        """Loopback SOCKS port of one endpoint (for workload tools that drive the tunnel)."""
        return self._ports[endpoint_name]

    @property
    def endpoint_names(self) -> list[str]:
        return list(self._ports)

    @property
    def alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def probe(
        self,
        endpoint_name: str,
        timeout: float = 8.0,
        *,
        target: ProbeTarget | None = None,
    ) -> ProbeResult:
        """Fetch the target through one endpoint. Never raises for tunnel failures.

        ``target`` overrides the session default for this call (social/AI smoke checks).
        """
        if self._proc is None:
            raise ProbeError("probe session is not running")
        if self._proc.poll() is not None:
            raise ProbeError("xray probe process has died; restart the session")
        dest = target or self._target
        port = self._ports[endpoint_name]
        started = time.monotonic()
        try:
            status = http_status_via_socks(port, dest, timeout)
        except (OSError, ConnectionError, ssl.SSLError, UnicodeError) as exc:
            return ProbeResult(endpoint_name, False, None, f"{type(exc).__name__}: {exc}"[:160])
        elapsed = (time.monotonic() - started) * 1000
        if status in dest.expect_status:
            return ProbeResult(endpoint_name, True, round(elapsed, 1))
        return ProbeResult(endpoint_name, False, None, f"unexpected HTTP status {status}")

    def probe_all(
        self, timeout: float = 8.0, *, target: ProbeTarget | None = None
    ) -> list[ProbeResult]:
        """Probe every endpoint concurrently; one slow endpoint cannot delay the others."""
        with ThreadPoolExecutor(max_workers=len(self._endpoints)) as pool:
            futures = [
                pool.submit(self.probe, ep.name, timeout, target=target) for ep in self._endpoints
            ]
            return [future.result() for future in futures]

    def wave(
        self,
        endpoint_name: str,
        count: int,
        *,
        timeout: float = 15.0,
        target: ProbeTarget | None = None,
        workers: int = 32,
    ) -> dict[str, float | int | str]:
        """Open ``count`` concurrent fetches through one endpoint (Iran-path load smoke)."""
        if count < 1:
            raise ValueError("count must be positive")
        dest = target or self._target
        with ThreadPoolExecutor(max_workers=min(workers, count)) as pool:
            results = list(
                pool.map(
                    lambda _: self.probe(endpoint_name, timeout, target=dest),
                    range(count),
                )
            )
        latencies = sorted(r.latency_ms for r in results if r.ok and r.latency_ms is not None)
        ok = sum(1 for r in results if r.ok)
        p95 = (
            latencies[max(0, int(len(latencies) * 0.95) - 1)]
            if len(latencies) >= 20
            else (latencies[-1] if latencies else 0.0)
        )
        return {
            "endpoint": endpoint_name,
            "requested": count,
            "ok": ok,
            "p50_ms": latencies[len(latencies) // 2] if latencies else 0.0,
            "p95_ms": p95,
        }
