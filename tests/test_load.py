"""Local load behaviour of a real Xray node (run with ``pytest -m load``).

These are the closest thing to the "no dead connections / many users" requirements that can be
shown without real servers: a REALITY node, a client, and a local echo target, all on loopback.
They are slow, so they are excluded from the default run.
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

import pytest

from shahrah.models import Endpoint, Profile, RealityServer, ServerSettings, Tuning, User
from shahrah.prober import socks5_connect
from shahrah.xray_client import render_probe_config
from shahrah.xray_config import PRIVATE_NETWORKS, render_server_config

pytestmark = [pytest.mark.load, pytest.mark.e2e]

TARGET = "www.cloudflare.com"
CONNECTIONS = 300
IDLE_LIMIT_S = 30  # the smallest idle limit the model allows


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def internet() -> bool:
    try:
        socket.create_connection((TARGET, 443), timeout=3).close()
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
    """A tiny TCP echo target that counts how many connections are open right now."""
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
        server = await asyncio.start_server(handle, "127.0.0.1", 0, backlog=1024)
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
    assert started.wait(5)
    try:
        yield state
    finally:
        for task in asyncio.all_tasks(loop):
            loop.call_soon_threadsafe(task.cancel)
        thread.join(timeout=3)


@contextmanager
def xray(xray_bin: str, config: dict[str, object], path: Path, port: int) -> Iterator[None]:
    path.write_text(json.dumps(config), encoding="utf-8")
    log = path.with_suffix(".log").open("wb")
    proc = subprocess.Popen([xray_bin, "run", "-c", str(path)], stdout=log, stderr=log)
    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
                break
            except OSError:
                if proc.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError(f"xray did not start: {path.name}") from None
                time.sleep(0.1)
        yield
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        log.close()


@dataclass
class Node:
    socks_port: int
    echo: Echo
    errors: list[str] = field(default_factory=list)


@pytest.fixture
def node(xray_bin: str, real_keypair: tuple[str, str], tmp_path: Path) -> Iterator[Node]:
    if not internet():
        pytest.skip("needs internet access (REALITY borrows a real TLS handshake)")
    private, public = real_keypair
    user = User.create("load-user")
    server_port, socks_port = free_port(), free_port()
    server = ServerSettings(
        profile=Profile.REALITY_VISION,
        reality=RealityServer(target_host=TARGET, private_key=private, short_ids=("ab12",)),
        listen="127.0.0.1",
        port=server_port,
        allow_non_443=True,
        tuning=Tuning(conn_idle_s=IDLE_LIMIT_S),
    )
    config = render_server_config(server, [user])
    # The echo target is on loopback, which the node blocks on purpose (see the SSRF test).
    config["routing"]["rules"] = [
        rule for rule in config["routing"]["rules"] if rule.get("ip") != list(PRIVATE_NETWORKS)
    ]
    # Xray 26 also refuses private targets inside the freedom outbound; allow them for the test.
    config["outbounds"][0]["settings"] = {"finalRules": [{"action": "allow"}]}
    endpoint = Endpoint(
        "load", "127.0.0.1", server_port, Profile.REALITY_VISION, public, "ab12", TARGET
    )
    client = render_probe_config([endpoint], user, [socks_port])
    with (
        echo_server() as echo,
        xray(xray_bin, config, tmp_path / "server.json", server_port),
        xray(xray_bin, client, tmp_path / "client.json", socks_port),
    ):
        yield Node(socks_port, echo)


def one_exchange(node: Node, payload: bytes) -> tuple[socket.socket | None, float]:
    started = time.perf_counter()
    try:
        sock = socks5_connect(node.socks_port, "127.0.0.1", node.echo.port, timeout=20)
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


def wave(node: Node, count: int) -> tuple[list[socket.socket], list[float]]:
    payload = b"x" * 1024
    with ThreadPoolExecutor(max_workers=64) as pool:
        results = list(pool.map(lambda _: one_exchange(node, payload), range(count)))
    socks = [s for s, _ in results if s is not None]
    return socks, [t for s, t in results if s is not None]


def test_many_concurrent_tunnels_work_and_idle_ones_are_reaped(node: Node) -> None:
    socks, latencies = wave(node, CONNECTIONS)
    try:
        assert len(socks) >= CONNECTIONS * 0.99, (
            f"only {len(socks)}/{CONNECTIONS} worked; errors: {sorted(set(node.errors))[:5]}"
        )
        p95 = statistics.quantiles(latencies, n=20)[-1]
        print(f"\nconnections ok={len(socks)} p95 setup+echo={p95 * 1000:.0f} ms")
        assert p95 < 10, "tunnel setup is unreasonably slow under concurrency"
        assert node.echo.open >= len(socks) * 0.95  # they really are all open on the target

        # Idle phase: nothing is sent. The node must close them after the idle limit.
        deadline = time.monotonic() + IDLE_LIMIT_S + 30
        while node.echo.open > 0 and time.monotonic() < deadline:
            time.sleep(1)
        assert node.echo.open == 0, f"{node.echo.open} idle connections were never reaped"

        # The client side must see the closure too (no half-open "dead" sockets).
        closed = 0
        for sock in socks:
            sock.settimeout(2)
            try:
                if sock.recv(1) == b"":
                    closed += 1
            except (TimeoutError, OSError):
                closed += 1  # a reset also means the connection is not silently dead
        assert closed >= len(socks) * 0.95
    finally:
        for sock in socks:
            sock.close()

    # And the node is still healthy afterwards.
    again, _ = wave(node, 50)
    try:
        assert len(again) >= 49
    finally:
        for sock in again:
            sock.close()


def test_the_node_refuses_to_proxy_to_its_own_private_network(
    xray_bin: str, real_keypair: tuple[str, str], tmp_path: Path
) -> None:
    """SSRF guard: a user must not be able to reach loopback/LAN services behind the node."""
    if not internet():
        pytest.skip("needs internet access (REALITY borrows a real TLS handshake)")
    private, public = real_keypair
    user = User.create("ssrf-user")
    server_port, socks_port = free_port(), free_port()
    server = ServerSettings(
        profile=Profile.REALITY_VISION,
        reality=RealityServer(target_host=TARGET, private_key=private, short_ids=("ab12",)),
        listen="127.0.0.1",
        port=server_port,
        allow_non_443=True,
    )
    endpoint = Endpoint(
        "ssrf", "127.0.0.1", server_port, Profile.REALITY_VISION, public, "ab12", TARGET
    )
    with (
        echo_server() as echo,
        xray(xray_bin, render_server_config(server, [user]), tmp_path / "s.json", server_port),
        xray(
            xray_bin,
            render_probe_config([endpoint], user, [socks_port]),
            tmp_path / "c.json",
            socks_port,
        ),
    ):
        sock, _ = one_exchange(Node(socks_port, echo), b"hello")
        if sock is not None:
            sock.close()
        assert sock is None and echo.accepted == 0
