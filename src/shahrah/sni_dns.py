"""SNI <-> DNS consistency for REALITY targets (net4people/bbs#668).

Iranian DPI (nDPI-style) compares the SNI a client sends with the IP it actually connects to:
if public DNS for the SNI never points at (or near) the server IP, the flow is an obvious
"borrowed" handshake and the node is flagged. Picking a famous site as the REALITY target is
therefore no longer enough; the target has to be *plausible for the node's address*.

Verdicts, strongest first:

* ``own-domain`` - the SNI resolves to the node IP itself (operator's own domain with a real
  certificate served by the target on the node). This is the only fully consistent mode.
* ``same-prefix`` - the SNI resolves into the node's /24 (IPv4) or /48 (IPv6): a neighbour on
  the same hosting network. Plausible, but a strict exact-match check would still flag it.
* ``mismatch`` - the SNI resolves only elsewhere: the #668 detection case.
* ``unresolved`` - no A/AAAA answer: suspicious and also unusable as a dial target.

Everything here is pure except :func:`system_resolver`; pass your own resolver in tests or to
resolve through a specific (e.g. in-country) DNS view.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from .models import ConfigError

Resolver = Callable[[str], Sequence[str]]

DEFAULT_V4_PREFIX = 24
DEFAULT_V6_PREFIX = 48


class SniDnsVerdict(StrEnum):
    OWN_DOMAIN = "own-domain"
    SAME_PREFIX = "same-prefix"
    MISMATCH = "mismatch"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class SniDnsCheck:
    sni: str
    node_ip: str
    verdict: SniDnsVerdict
    resolved: tuple[str, ...] = ()
    detail: str = ""

    def accepted(self, *, strict: bool = False) -> bool:
        """``strict`` accepts only ``own-domain``; otherwise a same-prefix neighbour is OK."""
        if strict:
            return self.verdict is SniDnsVerdict.OWN_DOMAIN
        return self.verdict in {SniDnsVerdict.OWN_DOMAIN, SniDnsVerdict.SAME_PREFIX}

    def as_dict(self) -> dict[str, object]:
        return {
            "sni": self.sni,
            "node_ip": self.node_ip,
            "verdict": str(self.verdict),
            "resolved": list(self.resolved),
            "detail": self.detail,
        }


def system_resolver(name: str) -> list[str]:
    """Resolve A and AAAA records with the OS resolver (I/O; not used by unit tests)."""
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    return sorted({str(info[4][0]) for info in infos})


def _network(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, v4: int, v6: int):
    prefix = v4 if ip.version == 4 else v6
    return ipaddress.ip_network(f"{ip}/{prefix}", strict=False)


def check(
    sni: str,
    node_ip: str,
    resolver: Resolver = system_resolver,
    *,
    v4_prefix: int = DEFAULT_V4_PREFIX,
    v6_prefix: int = DEFAULT_V6_PREFIX,
) -> SniDnsCheck:
    """Classify how plausible ``sni`` is for a server reachable at ``node_ip``."""
    try:
        node = ipaddress.ip_address(node_ip)
    except ValueError as exc:
        raise ConfigError(f"node_ip must be an IP address: {node_ip!r}") from exc
    if not 8 <= v4_prefix <= 32 or not 16 <= v6_prefix <= 128:
        raise ConfigError("prefix lengths out of range")
    resolved: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for raw in resolver(sni):
        try:
            resolved.append(ipaddress.ip_address(raw))
        except ValueError:
            continue
    names = tuple(sorted({str(ip) for ip in resolved}))
    if not resolved:
        return SniDnsCheck(sni, node_ip, SniDnsVerdict.UNRESOLVED, (), "no A/AAAA answer")
    if node in resolved:
        return SniDnsCheck(sni, node_ip, SniDnsVerdict.OWN_DOMAIN, names, "resolves to node")
    net = _network(node, v4_prefix, v6_prefix)
    if any(ip.version == node.version and ip in net for ip in resolved):
        return SniDnsCheck(
            sni, node_ip, SniDnsVerdict.SAME_PREFIX, names, f"neighbour inside {net}"
        )
    return SniDnsCheck(
        sni, node_ip, SniDnsVerdict.MISMATCH, names, f"no answer inside {net} (#668 risk)"
    )


def check_many(
    snis: Sequence[str],
    node_ip: str,
    resolver: Resolver = system_resolver,
    **kwargs: int,
) -> list[SniDnsCheck]:
    """Check several names; best verdicts first (stable by name)."""
    order = list(SniDnsVerdict)
    results = [check(s, node_ip, resolver, **kwargs) for s in snis]
    return sorted(results, key=lambda r: (order.index(r.verdict), r.sni))
