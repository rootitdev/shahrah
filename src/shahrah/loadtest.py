"""Concurrent tunnel load harness for capacity evidence.

Spins a REALITY server + client on loopback, opens many SOCKS tunnels to a local
echo target, reports success rate / latency, then waits for idle reaping. Used by
``shahrah load-test`` and ``pytest -m load``.
"""

from __future__ import annotations

import asyncio
import json
import socket
import statistics
import subprocess
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import ConfigError, Endpoint, Profile, RealityServer, ServerSettings, Tuning, User
from .prober import socks5_connect
from .xray_client import render_probe_config
from .xray_config import PRIVATE_NETWORKS, render_server_config

DEFAULT_TARGET = "www.cloudflare.com"
DEFAULT_IDLE_S = 30
MIN_CONNECTIONS = 10
MAX_CONNECTIONS = 5000


def raise_fd_limit(minimum: int = 1_048_576) -> int:
    """Raise the soft RLIMIT_NOFILE toward ``minimum`` (needed for 1k+ sockets).

    Returns the soft limit in effect afterwards. No-op on Windows / when the hard
    ceiling cannot be raised (never raises).
    """
    try:
        import resource  # Unix only
    except ImportError:
        return -1
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = min(max(minimum, soft), hard if hard > 0 else minimum)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        return soft
    except (ValueError, OSError):
        return -1


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def has_internet(host: str = DEFAULT_TARGET, port: int = 443, timeout: float = 3.0) -> bool:
    try:
        socket.create_connection((host, port), timeout=timeout).close()
    except OSError:
        return False
    return True


@dataclass
class Echo:
    port: int
    open: int = 0
    accepted: int = 0


@contextmanager
def echo_server() -> Iterator[Echo]:
    state = Echo(port=0)
    started = threading.Event()
    loop = asyncio.new_event_loop()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        state.open += 1
        state.accepted += 1
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            state.open -= 1
            writer.close()

    async def main() -> None:
        server = await asyncio.start_server(handle, "127.0.0.1", 0, backlog=4096)
        state.port = server.sockets[0].getsockname()[1]
        started.set()
        async with server:
            await server.serve_forever()

    def run() -> None:
        asyncio.set_event_loop(loop)
        with suppress(asyncio.CancelledError):
            loop.run_until_complete(main())

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    if not started.wait(5):
        raise ConfigError("echo server failed to start")
    try:
        yield state
    finally:
        for task in asyncio.all_tasks(loop):
            loop.call_soon_threadsafe(task.cancel)
        thread.join(timeout=3)


@contextmanager
def xray_process(xray_bin: str, config: dict[str, Any], path: Path, port: int) -> Iterator[None]:
    path.write_text(json.dumps(config), encoding="utf-8")
    log = path.with_suffix(".log").open("wb")
    proc = subprocess.Popen(  # noqa: S603 - fixed argv
        [xray_bin, "run", "-c", str(path)], stdout=log, stderr=log
    )
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
                break
            except OSError:
                if proc.poll() is not None or time.monotonic() > deadline:
                    raise ConfigError(f"xray did not start ({path.name})") from None
                time.sleep(0.1)
        yield
    finally:
        proc.terminate()
        with suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=8)
        if proc.poll() is None:
            proc.kill()
        log.close()


@dataclass
class LoadNode:
    socks_port: int
    echo: Echo
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class LoadReport:
    connections: int
    ok: int
    p50_ms: float
    p95_ms: float
    idle_reaped: bool
    echo_peak: int
    errors_sample: tuple[str, ...]
    duration_s: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "connections": self.connections,
            "ok": self.ok,
            "success_rate": round(self.ok / self.connections, 6) if self.connections else 0.0,
            "p50_ms": round(self.p50_ms, 2),
            "p95_ms": round(self.p95_ms, 2),
            "idle_reaped": self.idle_reaped,
            "echo_peak": self.echo_peak,
            "errors_sample": list(self.errors_sample),
            "duration_s": round(self.duration_s, 2),
        }


def _one_exchange(
    node: LoadNode, payload: bytes, timeout: float
) -> tuple[socket.socket | None, float]:
    started = time.perf_counter()
    try:
        sock = socks5_connect(node.socks_port, "127.0.0.1", node.echo.port, timeout=timeout)
        sock.sendall(payload)
        got = b""
        while len(got) < len(payload):
            chunk = sock.recv(len(payload) - len(got))
            if not chunk:
                raise ConnectionError("closed early")
            got += chunk
    except OSError as exc:
        node.errors.append(f"{type(exc).__name__}: {exc}")
        return None, time.perf_counter() - started
    return sock, time.perf_counter() - started


def wave(
    node: LoadNode, count: int, *, workers: int = 128, timeout: float = 30.0
) -> tuple[list[socket.socket], list[float]]:
    payload = b"x" * 1024
    with ThreadPoolExecutor(max_workers=max(8, min(workers, count))) as pool:
        results = list(pool.map(lambda _: _one_exchange(node, payload, timeout), range(count)))
    socks = [s for s, _ in results if s is not None]
    return socks, [t for s, t in results if s is not None]


@contextmanager
def load_node(
    xray_bin: str,
    workdir: Path,
    *,
    target: str = DEFAULT_TARGET,
    idle_s: int = DEFAULT_IDLE_S,
    public_key: str,
    private_key: str,
) -> Iterator[LoadNode]:
    user = User.create("load-user")
    server_port, socks_port = free_port(), free_port()
    server = ServerSettings(
        profile=Profile.REALITY_VISION,
        reality=RealityServer(target_host=target, private_key=private_key, short_ids=("ab12",)),
        listen="127.0.0.1",
        port=server_port,
        allow_non_443=True,
        tuning=Tuning(conn_idle_s=idle_s),
    )
    config = render_server_config(server, [user])
    config["routing"]["rules"] = [
        rule for rule in config["routing"]["rules"] if rule.get("ip") != list(PRIVATE_NETWORKS)
    ]
    config["outbounds"][0]["settings"] = {"finalRules": [{"action": "allow"}]}
    endpoint = Endpoint(
        "load", "127.0.0.1", server_port, Profile.REALITY_VISION, public_key, "ab12", target
    )
    client = render_probe_config([endpoint], user, [socks_port])
    with (
        echo_server() as echo,
        xray_process(xray_bin, config, workdir / "server.json", server_port),
        xray_process(xray_bin, client, workdir / "client.json", socks_port),
    ):
        yield LoadNode(socks_port, echo)


def run_load(
    xray_bin: str,
    workdir: Path,
    *,
    connections: int,
    target: str = DEFAULT_TARGET,
    idle_s: int = DEFAULT_IDLE_S,
    public_key: str,
    private_key: str,
    require_reap: bool = True,
) -> LoadReport:
    if connections < MIN_CONNECTIONS or connections > MAX_CONNECTIONS:
        raise ConfigError(f"connections must be between {MIN_CONNECTIONS} and {MAX_CONNECTIONS}")
    if not has_internet(target):
        raise ConfigError(f"no internet path to {target}:443 (REALITY needs a live cover site)")
    # Each tunnel burns several FDs (client socks + server + echo); default soft ulimit
    # (1024) dies around ~200-400 concurrent on Linux lab boxes.
    raise_fd_limit(max(65_536, connections * 16))
    started = time.perf_counter()
    with load_node(
        xray_bin,
        workdir,
        target=target,
        idle_s=idle_s,
        public_key=public_key,
        private_key=private_key,
    ) as node:
        socks, latencies = wave(node, connections)
        peak = node.echo.open
        try:
            p50 = statistics.median(latencies) * 1000 if latencies else 0.0
            p95 = (
                statistics.quantiles(latencies, n=20)[-1] * 1000
                if len(latencies) >= 20
                else (max(latencies) * 1000 if latencies else 0.0)
            )
            reaped = True
            if require_reap and socks:
                deadline = time.monotonic() + idle_s + 45
                while node.echo.open > 0 and time.monotonic() < deadline:
                    time.sleep(1)
                reaped = node.echo.open == 0
        finally:
            for sock in socks:
                sock.close()
        sample = tuple(sorted(set(node.errors))[:8])
        return LoadReport(
            connections=connections,
            ok=len(socks),
            p50_ms=p50,
            p95_ms=p95,
            idle_reaped=reaped,
            echo_peak=peak,
            errors_sample=sample,
            duration_s=time.perf_counter() - started,
        )
