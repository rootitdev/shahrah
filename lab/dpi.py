"""Lab-only SNI DPI on an NFQUEUE (stdlib only: raw AF_NETLINK, no libnetfilter_queue).

Models two censor behaviours reported on net4people:

* SNI allowlist: a TLS ClientHello whose SNI is not allowlisted gets the flow reset;
* SNI/DNS mismatch (bbs#668): an allowlisted SNI sent to an IP that the name does not resolve
  to (the classic "borrowed SNI" of REALITY) is reset as well.

Also reads the SNI out of QUIC v1 Initials (see quic.py); with --strict-udp, UDP flows whose
first packet is not readable QUIC are dropped ("unknown protocol" policy).

Verdicts: ACCEPT, or REPEAT with mark 1 so the iptables rules in censor.sh reset/drop the flow.
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from quic import client_hello_record  # noqa: E402

NETLINK_NETFILTER = 12
NFNL_SUBSYS_QUEUE = 3
MSG_PACKET, MSG_VERDICT, MSG_CONFIG = 0, 1, 2
NLM_F_REQUEST, NLM_F_ACK = 1, 4
CFG_CMD, CFG_PARAMS = 1, 2
CMD_BIND = 1
A_PACKET_HDR, A_VERDICT_HDR, A_MARK, A_PAYLOAD = 1, 2, 3, 10
NF_ACCEPT, NF_REPEAT = 1, 4
DUMP_DIR = Path(os.environ["DPI_DUMP"]) if os.environ.get("DPI_DUMP") else None


# --- pure parsing (unit-tested in tests/test_lab_units.py) -----------------------------------


def tcp_payload(ip_packet: bytes) -> tuple[str, bytes]:
    """Return (dst_ip, tcp payload) of an IPv4/TCP packet; ('', b'') otherwise."""
    if len(ip_packet) < 20 or ip_packet[0] >> 4 != 4 or ip_packet[9] != 6:
        return "", b""
    ihl = (ip_packet[0] & 0x0F) * 4
    if len(ip_packet) < ihl + 20:
        return "", b""
    doff = (ip_packet[ihl + 12] >> 4) * 4
    return socket.inet_ntoa(ip_packet[16:20]), ip_packet[ihl + doff :]


def parse_sni(payload: bytes) -> str | None:
    """SNI from a TLS ClientHello record (single segment), or None."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        pos = 9 + 2 + 32  # record hdr(5) + hs hdr(4) + version + random
        pos += 1 + payload[pos]  # session id
        (cs_len,) = struct.unpack_from("!H", payload, pos)
        pos += 2 + cs_len
        pos += 1 + payload[pos]  # compression
        (ext_total,) = struct.unpack_from("!H", payload, pos)
        pos += 2
        end = min(len(payload), pos + ext_total)
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack_from("!HH", payload, pos)
            pos += 4
            if ext_type == 0:  # server_name
                name_len = struct.unpack_from("!H", payload, pos + 3)[0]
                return payload[pos + 5 : pos + 5 + name_len].decode("ascii", "replace").lower()
            pos += ext_len
    except (IndexError, struct.error):
        return None
    return None


def udp_payload(ip_packet: bytes) -> tuple[str, int, bytes]:
    """(dst_ip, dst_port, payload) of an IPv4/UDP packet; ('', 0, b'') otherwise."""
    if len(ip_packet) < 28 or ip_packet[0] >> 4 != 4 or ip_packet[9] != 17:
        return "", 0, b""
    ihl = (ip_packet[0] & 0x0F) * 4
    port = int.from_bytes(ip_packet[ihl + 2 : ihl + 4], "big")
    return socket.inet_ntoa(ip_packet[16:20]), port, ip_packet[ihl + 8 :]


def judge_udp(
    payload: bytes, dst_ip: str, allow: dict[str, set[str]], strict: bool
) -> tuple[str | None, str]:
    """(sni, verdict) for the first packet of a UDP flow. QUIC Initials are decrypted and their
    SNI judged like TLS; anything unreadable passes, or is dropped in strict mode (the
    "unknown protocol" policy that hits salamander-obfuscated Hysteria2 and WireGuard)."""
    record = client_hello_record(payload)
    if record is None:
        return None, "block-unknown" if strict else "pass"
    sni = parse_sni(record)
    return sni, decide(sni, dst_ip, allow) if sni else ("block-unknown" if strict else "pass")


def flow_key(ip_packet: bytes) -> tuple[bytes, bytes] | None:
    """(src ip+port, dst ip+port) of an IPv4/TCP packet, for per-flow reassembly."""
    if len(ip_packet) < 20 or ip_packet[9] != 6:
        return None
    ihl = (ip_packet[0] & 0x0F) * 4
    return ip_packet[12:16] + ip_packet[ihl : ihl + 2], ip_packet[16:20] + ip_packet[
        ihl + 2 : ihl + 4
    ]


class HelloReassembler:
    """Joins a ClientHello split over several TCP segments.

    Chrome-like hellos carrying a post-quantum key share (X25519MLKEM768, ~1.2 KB) do not fit
    one segment, and with randomised extension order the SNI lands in the second segment about
    half the time; a single-segment parser lets those flows through (found in the lab).
    """

    MAX = 16 * 1024 + 5

    def __init__(self) -> None:
        self._buf: dict[tuple[bytes, bytes], bytes] = {}

    def feed(self, key: tuple[bytes, bytes] | None, payload: bytes) -> str | None:
        if key is None or not payload:
            return None
        if key in self._buf:
            data = self._buf.pop(key) + payload
        elif payload[0] == 0x16 and len(payload) >= 6 and payload[5] == 0x01:
            data = payload
        else:
            return None
        need = 5 + int.from_bytes(data[3:5], "big") if len(data) >= 5 else self.MAX
        if len(data) < min(need, self.MAX):
            if len(self._buf) > 4096:  # bound memory against floods of half-hellos
                self._buf.clear()
            self._buf[key] = data
            return None
        return parse_sni(data)


def load_allowlist(path: Path) -> dict[str, set[str]]:
    table: dict[str, set[str]] = {}
    for line in path.read_text().splitlines():
        parts = line.split()
        if parts and not parts[0].startswith("#"):
            table.setdefault(parts[0].lower(), set()).update(parts[1:])
    return table


def decide(sni: str | None, dst_ip: str, allow: dict[str, set[str]]) -> str:
    """'pass' | 'block-sni' | 'block-mismatch'. Non-hello packets (sni None) pass."""
    if sni is None:
        return "pass"
    if sni not in allow:
        return "block-sni"
    if allow[sni] and dst_ip not in allow[sni]:
        return "block-mismatch"
    return "pass"


# --- netlink plumbing ----------------------------------------------------------------------


def _attr(kind: int, data: bytes) -> bytes:
    raw = struct.pack("=HH", 4 + len(data), kind) + data
    return raw + b"\0" * (-len(raw) % 4)


def _msg(msg: int, queue: int, attrs: bytes, flags: int = NLM_F_REQUEST) -> bytes:
    body = struct.pack("!BBH", socket.AF_UNSPEC, 0, queue) + attrs
    kind = (NFNL_SUBSYS_QUEUE << 8) | msg
    return struct.pack("=IHHII", 16 + len(body), kind, flags, 0, 0) + body


def _attrs(data: bytes) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    pos = 0
    while pos + 4 <= len(data):
        length, kind = struct.unpack_from("=HH", data, pos)
        if length < 4:
            break
        out[kind & 0x7FFF] = data[pos + 4 : pos + length]
        pos += (length + 3) & ~3
    return out


def run(queue: int, allow: dict[str, set[str]], strict_udp: bool = False) -> None:
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
    sock.bind((0, 0))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
    cmd = struct.pack("!BBH", CMD_BIND, 0, socket.AF_INET)
    sock.send(_msg(MSG_CONFIG, queue, _attr(CFG_CMD, cmd), NLM_F_REQUEST | NLM_F_ACK))
    params = struct.pack("!IB", 0xFFFF, 2)  # copy whole packet
    sock.send(_msg(MSG_CONFIG, queue, _attr(CFG_PARAMS, params), NLM_F_REQUEST | NLM_F_ACK))
    print(f"dpi: bound to queue {queue}, allowlist {sorted(allow)}", flush=True)
    hellos = HelloReassembler()
    while True:
        data = sock.recv(1 << 17)
        pos = 0
        while pos + 16 <= len(data):
            length, kind = struct.unpack_from("=IH", data, pos)
            if length < 16:
                break
            if kind == (NFNL_SUBSYS_QUEUE << 8) | MSG_PACKET:
                attrs = _attrs(data[pos + 20 : pos + length])
                pkt_id = struct.unpack("!I", attrs[A_PACKET_HDR][:4])[0]
                packet = attrs.get(A_PAYLOAD, b"")
                if len(packet) > 9 and packet[9] == 17:
                    dst, _, payload = udp_payload(packet)
                    sni, verdict = judge_udp(payload, dst, allow, strict_udp)
                    if DUMP_DIR is not None and len(list(DUMP_DIR.glob("udp-*.bin"))) < 8:
                        (DUMP_DIR / f"udp-{pkt_id}.bin").write_bytes(payload)
                    if verdict != "pass" and sni is None:
                        print(f"dpi: udp -> {dst}: {verdict}", flush=True)
                else:
                    dst, payload = tcp_payload(packet)
                    sni = hellos.feed(flow_key(packet), payload)
                    verdict = decide(sni, dst, allow)
                if sni is not None:
                    print(f"dpi: {sni} -> {dst}: {verdict}", flush=True)
                if verdict == "pass":
                    v = _attr(A_VERDICT_HDR, struct.pack("!II", NF_ACCEPT, pkt_id))
                else:
                    v = _attr(A_VERDICT_HDR, struct.pack("!II", NF_REPEAT, pkt_id))
                    v += _attr(A_MARK, struct.pack("!I", 1))
                sock.send(_msg(MSG_VERDICT, queue, v))
            pos += (length + 3) & ~3


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--queue", type=int, default=7)
    ap.add_argument("--allow", type=Path, required=True)
    ap.add_argument("--strict-udp", action="store_true")
    args = ap.parse_args()
    run(args.queue, load_allowlist(args.allow), args.strict_udp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
