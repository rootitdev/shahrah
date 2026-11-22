"""Local load behaviour of a real Xray node (run with ``pytest -m load``).

These are the closest thing to the "no dead connections / many users" requirements that can be
shown without Iranian-path servers: a REALITY node, a client, and a local echo target.
They are slow, so they are excluded from the default run. Operators can also run
``shahrah load-test --connections N``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shahrah import loadtest
from shahrah.models import Endpoint, Profile, RealityServer, ServerSettings, User
from shahrah.xray_client import render_probe_config
from shahrah.xray_config import render_server_config

pytestmark = [pytest.mark.load, pytest.mark.e2e]

CONNECTIONS = 300


def test_many_concurrent_tunnels_work_and_idle_ones_are_reaped(
    xray_bin: str, real_keypair: tuple[str, str], tmp_path: Path
) -> None:
    private, public = real_keypair
    report = loadtest.run_load(
        xray_bin,
        tmp_path,
        connections=CONNECTIONS,
        public_key=public,
        private_key=private,
        require_reap=True,
    )
    print(
        f"\nload ok={report.ok}/{report.connections} "
        f"p95={report.p95_ms:.0f}ms peak={report.echo_peak} reaped={report.idle_reaped}"
    )
    assert report.ok >= CONNECTIONS * 0.99, report.errors_sample
    assert report.p95_ms < 10_000, "tunnel setup is unreasonably slow under concurrency"
    assert report.idle_reaped
    assert report.echo_peak >= report.ok * 0.9


def test_the_node_refuses_to_proxy_to_its_own_private_network(
    xray_bin: str, real_keypair: tuple[str, str], tmp_path: Path
) -> None:
    """SSRF guard: a user must not be able to reach loopback/LAN services behind the node."""
    if not loadtest.has_internet():
        pytest.skip("needs internet access (REALITY borrows a real TLS handshake)")
    private, public = real_keypair
    user = User.create("ssrf-user")
    server_port, socks_port = loadtest.free_port(), loadtest.free_port()
    server = ServerSettings(
        profile=Profile.REALITY_VISION,
        reality=RealityServer(
            target_host=loadtest.DEFAULT_TARGET, private_key=private, short_ids=("ab12",)
        ),
        listen="127.0.0.1",
        port=server_port,
        allow_non_443=True,
    )
    endpoint = Endpoint(
        "ssrf",
        "127.0.0.1",
        server_port,
        Profile.REALITY_VISION,
        public,
        "ab12",
        loadtest.DEFAULT_TARGET,
    )
    with (
        loadtest.echo_server() as echo,
        loadtest.xray_process(
            xray_bin, render_server_config(server, [user]), tmp_path / "s.json", server_port
        ),
        loadtest.xray_process(
            xray_bin,
            render_probe_config([endpoint], user, [socks_port]),
            tmp_path / "c.json",
            socks_port,
        ),
    ):
        node = loadtest.LoadNode(socks_port, echo)
        sock, _ = loadtest._one_exchange(node, b"hello", timeout=10)
        if sock is not None:
            sock.close()
        assert sock is None and echo.accepted == 0
