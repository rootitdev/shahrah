from __future__ import annotations

import socket
import threading
from pathlib import Path

import pytest

from shahrah import paqet
from shahrah.cli import main
from shahrah.models import ConfigError
from shahrah.oracle import Mode
from shahrah.prober import ProbeTarget, probe_socks

KEY = "k" * 24
MAC = "AA:BB:CC:DD:EE:01"


def test_render_server_and_client() -> None:
    server = paqet.render_server(paqet.PaqetServer("eth0", "203.0.113.10", MAC, KEY, 9999))
    assert 'role: "server"' in server and '  addr: ":9999"' in server
    assert '"203.0.113.10:9999"' in server and '"aa:bb:cc:dd:ee:01"' in server
    assert f'key: "{KEY}"' in server
    client = paqet.render_client(
        paqet.PaqetClient("ens3", "10.0.0.5", MAC, "203.0.113.10", KEY, 9999)
    )
    assert '"10.0.0.5:0"' in client and '"203.0.113.10:9999"' in client
    assert '- listen: "127.0.0.1:1080"' in client


@pytest.mark.parametrize(
    "kwargs",
    [
        {"port": 443},
        {"port": 80},
        {"port": 1000},
        {"router_mac": "nope"},
        {"key": "short"},
        {"key": 'x"' * 10},
        {"interface": "eth0; rm -rf /"},
        {"ipv4": "example.com"},
        {"kcp_mode": "turbo"},
    ],
)
def test_server_validation(kwargs: dict) -> None:
    base = {"interface": "eth0", "ipv4": "203.0.113.10", "router_mac": MAC, "key": KEY}
    with pytest.raises(ConfigError):
        paqet.PaqetServer(**{**base, **kwargs})


def test_client_refuses_public_socks() -> None:
    with pytest.raises(ConfigError):
        paqet.PaqetClient("eth0", "10.0.0.5", MAC, "203.0.113.10", KEY, socks_listen="0.0.0.0:1080")


def test_firewall_rules_match_upstream() -> None:
    rules = [" ".join(r) for r in paqet.server_firewall_rules(9999)]
    assert "iptables -t raw -A PREROUTING -p tcp --dport 9999 -j NOTRACK" in rules
    assert any("--tcp-flags RST RST -j DROP" in r for r in rules)
    with pytest.raises(ConfigError):
        paqet.server_firewall_rules(443)


def test_pinned_digests_are_well_formed() -> None:
    assert all(len(h) == 64 and int(h, 16) >= 0 for h in paqet.PAQET_SHA256.values())
    text = (Path(__file__).parent.parent / "deploy" / "install.sh").read_text()
    for digest in paqet.PAQET_SHA256.values():
        assert digest in text
    assert paqet.PAQET_VERSION in text
    assert text.index("checksum mismatch for paqet") < text.index('install -m 0755 "$dir/paqet')
    # Relay installs the client toward --ww-peer; exit/node keep the server.
    assert '[[ "$ROLE" == "relay" ]]' in text
    assert "paqet-config client" in text
    assert "shahrah-paqet-client.service" in text


def test_crisis_hook_starts_and_stops_client() -> None:
    calls: list[list[str]] = []
    hook = paqet.crisis_hook(runner=lambda argv: calls.append(list(argv)))
    hook(Mode.NORMAL, Mode.DEGRADED)
    hook(Mode.DEGRADED, Mode.RESTRICTED)
    hook(Mode.RESTRICTED, Mode.OUTAGE)  # still in crisis: no second start
    hook(Mode.OUTAGE, Mode.NORMAL)
    assert calls == [
        ["systemctl", "start", paqet.CLIENT_UNIT],
        ["systemctl", "stop", paqet.CLIENT_UNIT],
    ]


def test_cli_renders_and_creates_private_key(tmp_path: Path, capsys) -> None:
    key = tmp_path / "paqet.key"
    out = tmp_path / "paqet.yaml"
    argv = ["paqet-config", "server", "--ip", "203.0.113.10", "--router-mac", MAC]
    assert main([*argv, "--key-file", str(key), "--out", str(out)]) == 0
    assert key.read_text().strip() in out.read_text()
    assert main(["paqet-config", "firewall", "--port", "8888"]) == 0
    assert "NOTRACK" in capsys.readouterr().out
    assert main(["paqet-config", "unit", "--unit-role", "client"]) == 0
    assert "CAP_NET_RAW" in capsys.readouterr().out


def _fake_socks_http(status: int) -> int:
    """Minimal SOCKS5 server answering one plain-HTTP request with ``status``."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def run() -> None:
        conn, _ = srv.accept()
        with conn:
            conn.recv(3)
            conn.sendall(b"\x05\x00")
            head = conn.recv(5)
            conn.recv(head[4] + 2)
            conn.sendall(b"\x05\x00\x00\x01" + bytes(6))
            conn.recv(4096)
            conn.sendall(f"HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n".encode())
        srv.close()

    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1]


def test_probe_socks_reports_paqet_path() -> None:
    target = ProbeTarget("www.example.com", 80, "/", tls=False, expect_status=frozenset({204}))
    ok = probe_socks("paqet", _fake_socks_http(204), target, timeout=3)
    assert ok.ok and ok.endpoint == "paqet" and ok.latency_ms is not None
    bad = probe_socks("paqet", _fake_socks_http(500), target, timeout=3)
    assert not bad.ok and "500" in bad.detail
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()  # nothing listens: the crisis path is down
    dead = probe_socks("paqet", port, target, timeout=1)
    assert not dead.ok
