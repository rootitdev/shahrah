"""Pure parts of the lab censor (DPI parser, poisoning resolver) and the lab marker."""

from __future__ import annotations

import os
import socket
import ssl
import struct
import subprocess
import sys
from pathlib import Path

import pytest

LAB = Path(__file__).resolve().parent.parent / "lab"
sys.path.insert(0, str(LAB))

import dnsd  # noqa: E402
import dpi  # noqa: E402


def _client_hello(sni: str) -> bytes:
    """A real ClientHello produced by the stdlib TLS stack (memory BIO, no network)."""
    ctx = ssl.create_default_context()
    out, inc = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=sni)
    with pytest.raises(ssl.SSLWantReadError):
        obj.do_handshake()
    return out.read()


def _ipv4_tcp(dst: str, payload: bytes) -> bytes:
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40 + len(payload),
        0,
        0,
        64,
        6,
        0,
        socket.inet_aton("10.0.1.2"),
        socket.inet_aton(dst),
    )
    tcp = struct.pack("!HHIIBBHHH", 40000, 443, 0, 0, 5 << 4, 0x18, 65535, 0, 0)
    return ip + tcp + payload


ALLOW = {"cover.lab": {"23.5.100.2"}, "iran.lab": {"10.0.2.2"}}


def test_sni_is_parsed_from_a_real_client_hello() -> None:
    dst, payload = dpi.tcp_payload(_ipv4_tcp("10.0.4.2", _client_hello("www.example.org")))
    assert dst == "10.0.4.2"
    assert dpi.parse_sni(payload) == "www.example.org"
    assert dpi.parse_sni(b"GET / HTTP/1.1\r\n") is None


def test_allowlist_and_sni_dns_mismatch() -> None:
    assert dpi.decide("cover.lab", "23.5.100.2", ALLOW) == "pass"
    assert dpi.decide("cover.lab", "10.0.4.2", ALLOW) == "block-mismatch"  # borrowed SNI
    assert dpi.decide("blocked.example", "23.5.100.2", ALLOW) == "block-sni"
    assert dpi.decide(None, "10.0.4.2", ALLOW) == "pass"


def _query(name: str) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def test_resolver_truth_and_poison() -> None:
    truth = dnsd.answer(_query("exit.lab"), "truth")
    assert truth.endswith(socket.inet_aton("10.0.4.2"))
    poisoned = dnsd.answer(_query("exit.lab"), "poison")
    assert poisoned.endswith(socket.inet_aton(dnsd.SINKHOLE))
    assert dnsd.answer(_query("cover.lab"), "poison").endswith(socket.inet_aton("23.5.100.2"))


@pytest.mark.lab
@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0 or not os.environ.get("SHAHRAH_LAB"),
    reason="full censorship lab: run as root with SHAHRAH_LAB=1 (Linux/WSL, ~10 min)",
)
def test_full_lab_brain_failover() -> None:
    """Brings the lab up, runs the brain failover scenario, tears it down."""
    result = subprocess.run(["bash", str(LAB / "run.sh"), "brain"], timeout=1200, check=False)
    assert result.returncode == 0
