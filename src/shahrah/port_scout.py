"""Scored bank of TCP/UDP ports for crisis failover (sibling of sni-bank).

Well-known ports (80/443/53/…) stay available as crisis defaults, but the scout prefers
high, unused ports that are still reachable from Iranian vantages. Results are hostnames-
free: only port numbers, proto, scores and booleans — no secrets.
"""

from __future__ import annotations

import json
import socket
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .models import ConfigError, validate_port

BANK_VERSION = 1
DEFAULT_TTL_S = 12 * 3600.0
WELL_KNOWN = frozenset({80, 443, 53, 22, 25, 465, 587, 993, 995, 8080, 8443, 2052, 2053})
# Default probe set: avoid the famous few; mix of HTTPS-alts, gaming, and high ephemeral-ish.
SEED_TCP: tuple[int, ...] = (
    8443,
    2053,
    2083,
    2087,
    2096,
    8880,
    9443,
    10443,
    12443,
    18080,
    28080,
    4430,
    8444,
    10444,
)
SEED_UDP: tuple[int, ...] = (
    8443, 443, 500, 4500, 2408, 3478, 5349, 19302, 20000, 30000, 40000, 50000
)

Probe = Callable[[str, int, str, float], "ProbeResult"]  # host, port, proto, timeout


@dataclass(frozen=True, slots=True)
class ProbeResult:
    port: int
    proto: str  # tcp|udp
    ok: bool
    latency_ms: float | None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Observation:
    vantage: str
    asn: int | None
    at: float
    ok: bool
    latency_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "vantage": self.vantage,
            "asn": self.asn,
            "at": self.at,
            "ok": self.ok,
            "latency_ms": self.latency_ms,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Observation:
        asn = data.get("asn")
        return cls(
            vantage=str(data["vantage"]),
            asn=int(asn) if asn is not None else None,
            at=float(data["at"]),
            ok=bool(data["ok"]),
            latency_ms=float(data["latency_ms"]) if data.get("latency_ms") is not None else None,
        )


@dataclass(frozen=True, slots=True)
class Candidate:
    port: int
    proto: str
    verified_at: float = 0.0
    ok: bool = False
    latency_ms: float | None = None
    observations: tuple[Observation, ...] = ()
    assigned_to: str = ""  # user/group label when reserved

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "proto": self.proto,
            "verified_at": self.verified_at,
            "ok": self.ok,
            "latency_ms": self.latency_ms,
            "observations": [o.to_dict() for o in self.observations],
            "assigned_to": self.assigned_to,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Candidate:
        return cls(
            port=validate_port(int(data["port"])),
            proto=_proto(str(data.get("proto", "tcp"))),
            verified_at=float(data.get("verified_at", 0.0)),
            ok=bool(data.get("ok", False)),
            latency_ms=float(data["latency_ms"]) if data.get("latency_ms") is not None else None,
            observations=tuple(Observation.from_dict(o) for o in data.get("observations") or ()),
            assigned_to=str(data.get("assigned_to") or ""),
        )

    def expired(self, now: float, ttl_s: float = DEFAULT_TTL_S) -> bool:
        return now - self.verified_at > ttl_s


@dataclass(frozen=True, slots=True)
class Score:
    port: int
    proto: str
    total: float
    usable: bool
    expired: bool
    factors: Mapping[str, float]
    reasons: tuple[str, ...]


def _proto(value: str) -> str:
    v = value.lower()
    if v not in {"tcp", "udp"}:
        raise ConfigError(f"proto must be tcp or udp: {value!r}")
    return v


def tcp_probe(host: str, port: int, proto: str, timeout_s: float) -> ProbeResult:
    if proto != "tcp":
        return ProbeResult(port, proto, False, None, "tcp_probe only")
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return ProbeResult(port, "tcp", True, (time.perf_counter() - t0) * 1000, "connected")
    except OSError as exc:
        return ProbeResult(port, "tcp", False, None, type(exc).__name__)


def udp_probe(host: str, port: int, proto: str, timeout_s: float) -> ProbeResult:
    """Best-effort UDP reachability: send a datagram; 'ok' if no immediate ICMP refuse.

    True UDP liveness needs an application reply; this only filters obvious blocks.
    """
    if proto != "udp":
        return ProbeResult(port, proto, False, None, "udp_probe only")
    t0 = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_s)
    try:
        sock.sendto(b"\x00" * 16, (host, port))
        try:
            sock.recvfrom(64)
            return ProbeResult(port, "udp", True, (time.perf_counter() - t0) * 1000, "reply")
        except TimeoutError:
            # No reply is common; treat as soft-ok (packet left the host).
            return ProbeResult(port, "udp", True, (time.perf_counter() - t0) * 1000, "sent")
    except OSError as exc:
        return ProbeResult(port, "udp", False, None, type(exc).__name__)
    finally:
        sock.close()


def default_probe(host: str, port: int, proto: str, timeout_s: float) -> ProbeResult:
    return tcp_probe(host, port, proto, timeout_s) if proto == "tcp" else udp_probe(
        host, port, proto, timeout_s
    )


@dataclass(frozen=True, slots=True)
class PortBank:
    candidates: tuple[Candidate, ...] = ()
    target_host: str = ""  # host probed from the vantage (usually the EXIT IP/domain)

    def get(self, port: int, proto: str) -> Candidate | None:
        proto = _proto(proto)
        for c in self.candidates:
            if c.port == port and c.proto == proto:
                return c
        return None

    def upsert(self, cand: Candidate) -> PortBank:
        rest = tuple(
            c for c in self.candidates
            if not (c.port == cand.port and c.proto == cand.proto)
        )
        return replace(self, candidates=(*rest, cand))

    def add(self, ports: Iterable[int], proto: str, now: float) -> PortBank:
        proto = _proto(proto)
        bank = self
        for port in ports:
            validate_port(port)
            if bank.get(port, proto) is None:
                bank = bank.upsert(Candidate(port=port, proto=proto, verified_at=0.0))
        return bank

    def ranked(
        self, now: float, *, proto: str | None = None, ttl_s: float = DEFAULT_TTL_S
    ) -> list[Score]:
        out: list[Score] = []
        for c in self.candidates:
            if proto and c.proto != proto:
                continue
            out.append(score(c, now, ttl_s=ttl_s))
        return sorted(out, key=lambda s: (not s.usable, s.port in WELL_KNOWN, -s.total, s.port))


def score(cand: Candidate, now: float, *, ttl_s: float = DEFAULT_TTL_S) -> Score:
    reasons: list[str] = []
    expired = cand.expired(now, ttl_s)
    if expired:
        reasons.append("not verified within TTL")
    if not cand.ok:
        reasons.append("last probe failed")
    well = 0.0 if cand.port in WELL_KNOWN else 1.0
    if cand.port in WELL_KNOWN:
        reasons.append("well-known port (prefer high ports)")
    lat = 1.0
    if cand.latency_ms is not None:
        lat = max(0.0, min(1.0, 1.0 - (cand.latency_ms / 500.0)))
    fresh_ok = [o for o in cand.observations if now - o.at <= ttl_s and o.ok]
    vant = min(1.0, len({o.vantage for o in fresh_ok}) / 2.0) if fresh_ok else 0.0
    if not fresh_ok:
        reasons.append("no fresh vantage OK")
    factors = {"reach": 1.0 if cand.ok else 0.0, "latency": lat, "vantage": vant, "obscurity": well}
    total = 0.0
    if cand.ok and not expired:
        total = 40 * factors["reach"] + 25 * lat + 25 * vant + 10 * well
    usable = total >= 40 and cand.ok and not expired
    return Score(cand.port, cand.proto, total, usable, expired, factors, tuple(reasons))


def refresh(
    bank: PortBank,
    now: float | None = None,
    *,
    only_due: bool = True,
    ttl_s: float = DEFAULT_TTL_S,
    timeout_s: float = 3.0,
    probe: Probe | None = None,
    vantage: str = "local",
    asn: int | None = None,
) -> PortBank:
    if not bank.target_host:
        raise ConfigError("port-scout bank needs target_host (EXIT IP or domain)")
    now = time.time() if now is None else now
    probe = probe or default_probe
    for cand in bank.candidates:
        if only_due and not cand.expired(now, ttl_s * 0.75):
            continue
        result = probe(bank.target_host, cand.port, cand.proto, timeout_s)
        obs = Observation(
            vantage=vantage, asn=asn, at=now, ok=result.ok, latency_ms=result.latency_ms
        )
        kept = (*tuple(o for o in cand.observations if o.vantage != vantage), obs)
        bank = bank.upsert(
            replace(
                cand,
                verified_at=now if result.ok else cand.verified_at,
                ok=result.ok,
                latency_ms=result.latency_ms,
                observations=kept,
            )
        )
    return bank


def assign(bank: PortBank, port: int, proto: str, label: str) -> PortBank:
    cand = bank.get(port, proto)
    if cand is None:
        raise ConfigError(f"unknown candidate {proto}/{port}")
    return bank.upsert(replace(cand, assigned_to=label))


def pick(
    bank: PortBank,
    now: float,
    *,
    proto: str = "tcp",
    prefer_unassigned: bool = True,
) -> Candidate | None:
    ranked = bank.ranked(now, proto=proto)
    for s in ranked:
        if not s.usable:
            continue
        cand = bank.get(s.port, s.proto)
        if cand is None:
            continue
        if prefer_unassigned and cand.assigned_to:
            continue
        return cand
    for s in ranked:
        if s.usable:
            return bank.get(s.port, s.proto)
    return None


def load_bank(path: Path) -> PortBank:
    if not path.exists():
        return PortBank()
    data = json.loads(path.read_text(encoding="utf-8"))
    if int(data.get("version", 0)) != BANK_VERSION:
        raise ConfigError("unsupported port-scout bank version")
    return PortBank(
        candidates=tuple(Candidate.from_dict(c) for c in data.get("candidates") or ()),
        target_host=str(data.get("target_host") or ""),
    )


def save_bank(path: Path, bank: PortBank) -> None:
    payload = {
        "version": BANK_VERSION,
        "target_host": bank.target_host,
        "candidates": [c.to_dict() for c in bank.candidates],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def seed(
    bank: PortBank, *, tcp: Sequence[int] = SEED_TCP, udp: Sequence[int] = SEED_UDP
) -> PortBank:
    now = time.time()
    bank = bank.add(tcp, "tcp", now)
    bank = bank.add(udp, "udp", now)
    return bank
