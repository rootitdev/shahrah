"""Lab resolver on the censor (stdlib). Truthful by default; in poison mode every name that is
not allowlisted resolves to a sinkhole, like Iranian resolvers answering 10.10.34.x."""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

ZONE = {
    "cover.lab": "198.18.5.2",
    "exit.lab": "10.0.4.2",
    "iran.lab": "10.0.2.2",
    "cdn.lab": "198.18.6.2",
}
ALLOW = {"cover.lab", "iran.lab", "cdn.lab"}
SINKHOLE = "10.10.34.34"
MODE_FILE = Path("/run/shahrah-lab/dns_mode")


def qname(packet: bytes) -> tuple[str, int]:
    labels, pos = [], 12
    while packet[pos]:
        n = packet[pos]
        labels.append(packet[pos + 1 : pos + 1 + n].decode("ascii", "replace"))
        pos += 1 + n
    return ".".join(labels).lower(), pos + 5  # end of question (null + qtype + qclass)


def answer(packet: bytes, mode: str) -> bytes:
    name, qend = qname(packet)
    qtype = struct.unpack_from("!H", packet, qend - 4)[0]
    ip = ZONE.get(name)
    if mode == "poison" and name not in ALLOW:
        ip = SINKHOLE
    flags = 0x8180 if ip else 0x8183  # NOERROR / NXDOMAIN
    an = 1 if ip and qtype == 1 else 0
    head = packet[:2] + struct.pack("!HHHHH", flags, 1, an, 0, 0)
    body = packet[12:qend]
    if an:
        body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton(ip)
    return head + body


def main() -> int:
    addr = sys.argv[1] if len(sys.argv) > 1 else "10.0.1.1"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((addr, 53))
    while True:
        data, peer = sock.recvfrom(1500)
        try:
            mode = MODE_FILE.read_text().strip()
        except OSError:
            mode = "truth"
        try:
            sock.sendto(answer(data, mode), peer)
        except (IndexError, struct.error, UnicodeError):
            continue


if __name__ == "__main__":
    sys.exit(main())
