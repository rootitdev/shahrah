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


ALLOW = {"cover.lab": {"198.18.5.2"}, "iran.lab": {"10.0.2.2"}}


def test_sni_is_parsed_from_a_real_client_hello() -> None:
    dst, payload = dpi.tcp_payload(_ipv4_tcp("10.0.4.2", _client_hello("www.example.org")))
    assert dst == "10.0.4.2"
    assert dpi.parse_sni(payload) == "www.example.org"
    assert dpi.parse_sni(b"GET / HTTP/1.1\r\n") is None


def test_sni_found_when_client_hello_spans_segments() -> None:
    hello = _client_hello("blocked.example")
    first, second = hello[:60], hello[60:]
    asm = dpi.HelloReassembler()
    key = (b"a", b"b")
    assert dpi.parse_sni(first) is None
    assert asm.feed(key, first) is None
    assert asm.feed(key, second) == "blocked.example"
    assert asm.feed((b"c", b"d"), b"GET / HTTP/1.1\r\n") is None


def test_allowlist_and_sni_dns_mismatch() -> None:
    assert dpi.decide("cover.lab", "198.18.5.2", ALLOW) == "pass"
    assert dpi.decide("cover.lab", "10.0.4.2", ALLOW) == "block-mismatch"  # borrowed SNI
    assert dpi.decide("blocked.example", "198.18.5.2", ALLOW) == "block-sni"
    assert dpi.decide(None, "10.0.4.2", ALLOW) == "pass"


def _query(name: str) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def test_resolver_truth_and_poison() -> None:
    truth = dnsd.answer(_query("exit.lab"), "truth")
    assert truth.endswith(socket.inet_aton("10.0.4.2"))
    poisoned = dnsd.answer(_query("exit.lab"), "poison")
    assert poisoned.endswith(socket.inet_aton(dnsd.SINKHOLE))
    assert dnsd.answer(_query("cover.lab"), "poison").endswith(socket.inet_aton("198.18.5.2"))


@pytest.mark.lab
@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0 or not os.environ.get("SHAHRAH_LAB"),
    reason="full censorship lab: run as root with SHAHRAH_LAB=1 (Linux/WSL, ~10 min)",
)
def test_full_lab_brain_failover() -> None:
    """Brings the lab up, runs the brain failover scenario, tears it down."""
    result = subprocess.run(["bash", str(LAB / "run.sh"), "brain"], timeout=1200, check=False)
    assert result.returncode == 0


import quic  # noqa: E402


def _quic_initial(dcid: bytes, handshake: bytes) -> bytes:
    """A client QUIC v1 Initial carrying ``handshake`` in one CRYPTO frame (RFC 9001 sec. 5)."""
    return _quic_initial_at(dcid, 0, handshake)


def _quic_initial_at(dcid: bytes, offset: int, data: bytes) -> bytes:
    key, iv, hp = quic.initial_keys(dcid)
    handshake = data
    frame = (
        b"\x06"
        + (0x4000 | offset).to_bytes(2, "big")
        + (0x4000 | len(handshake)).to_bytes(2, "big")
        + handshake
    )
    plain = frame + b"\x00" * max(0, 1162 - len(frame))
    pn = b"\x02"
    length = len(pn) + len(plain) + 16
    head = (
        b"\xc0\x00\x00\x00\x01"
        + bytes([len(dcid)])
        + dcid
        + b"\x00"
        + b"\x00"
        + (0x4000 | length).to_bytes(2, "big")
    )
    nonce = bytes(a ^ b for a, b in zip(iv, pn.rjust(12, b"\0"), strict=True))
    body = quic.aes128_ctr(key, nonce + b"\x00\x00\x00\x02", plain) + b"\x00" * 16
    packet = bytearray(head + pn + body)
    mask = quic.aes128_encrypt_block(hp, bytes(packet[len(head) + 4 : len(head) + 20]))
    packet[0] ^= mask[0] & 0x0F
    packet[len(head)] ^= mask[1]
    return bytes(packet)


def test_aes_and_quic_initial_keys_match_published_vectors() -> None:
    fips = quic.aes128_encrypt_block(
        bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
    )
    assert fips.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"  # FIPS-197 C.1
    key, iv, hp = quic.initial_keys(bytes.fromhex("8394c8f03e515708"))  # RFC 9001 A.1
    assert key.hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert iv.hex() == "fa044b2f42a3fd3b46fb255c"
    assert hp.hex() == "9f50449e04a0e810283a1e9933adedd2"
    sample = bytes.fromhex("d1b1c98dd7689fb8ec11d242b123dc9b")  # RFC 9001 A.2
    assert quic.aes128_encrypt_block(hp, sample)[:5].hex() == "437b9aec36"


def test_dpi_reads_sni_from_quic_initial_and_strict_mode_drops_opaque_udp() -> None:
    handshake = _client_hello("exit.lab")[5:]
    packet = _quic_initial(bytes.fromhex("8394c8f03e515708"), handshake)
    assert dpi.parse_sni(quic.client_hello_record(packet) or b"") == "exit.lab"
    assert dpi.judge_udp(packet, "10.0.4.2", ALLOW, strict=False) == ("exit.lab", "block-sni")
    opaque = bytes(range(256)) * 5  # salamander-obfuscated Hysteria2 looks like this
    assert dpi.judge_udp(opaque, "10.0.4.2", ALLOW, strict=False) == (None, "pass")
    assert dpi.judge_udp(opaque, "10.0.4.2", ALLOW, strict=True) == (None, "block-unknown")


def test_quic_hello_split_over_two_initials_is_reassembled() -> None:
    """quic-go sends a ~2 KB post-quantum hello in two Initials with shuffled CRYPTO frames."""
    handshake = _client_hello("exit.lab")[5:]
    dcid = bytes.fromhex("1122334455667788")
    cut = 20
    first = _quic_initial(dcid, handshake[:cut])
    second_frame = _quic_initial_at(dcid, cut, handshake[cut:])
    asm = quic.InitialReassembler()
    assert dpi.judge_udp(first, "10.0.4.2", ALLOW, False, asm) == (None, "pass")
    assert dpi.judge_udp(second_frame, "10.0.4.2", ALLOW, False, asm) == ("exit.lab", "block-sni")
