"""A scored, expiring bank of SNI / REALITY-target candidates.

Field reports (net4people bbs#628, #668) show three ways SNIs die in Iran: the DPI compares the
SNI with the destination IP (a "borrowed" famous name on our IP is flagged); young or
over-used names get added to the block list, sometimes within a day; and what passes on
one ASN is dead on another. A one-off ``sni-scout`` ranking therefore goes stale quickly.

The bank keeps candidates (foreign REALITY targets and Iran-side names for domestic relays)
with per-vantage observations. Each observation is a TLS check from one network/ASN. Every
candidate gets a 0-100 score from these factors:

=================  ======  ===========================================================
factor             weight  meaning
=================  ======  ===========================================================
tls                gate    TLS 1.3 with a publicly valid certificate (else score 0)
reality            15      h2 ALPN offered, not on the risky-suffix list
latency            15      handshake time from the exit (REALITY dials it per connection)
dns                35      SNI<->IP plausibility for our node (own-domain > same-prefix)
cert               10      days until the certificate expires (a dying cert is a tell)
vantage            25      share of fresh vantages (ASNs) that saw it pass; any "blocked"
                           sighting from an Iranian ASN is a heavy penalty
=================  ======  ===========================================================

Verification is short-lived: a candidate not re-verified within ``ttl_s`` (default 12 h)
is *expired* and cannot be picked; :func:`rotation` says when the active SNI should move.
Everything except :func:`refresh` (which calls the network through ``sni_scout``) is pure.
The bank file holds hostnames, scores and booleans only: no secrets and no user data.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from . import sni_dns, sni_scout
from .models import RISKY_TARGET_SUFFIXES, ConfigError, is_ip, validate_host

BANK_VERSION = 1
DEFAULT_TTL_S = 12 * 3600.0  # some names die in < 24 h; re-verify twice a day
VANTAGE_MAX_AGE_S = 6 * 3600.0
MIN_PICK_SCORE = 50.0
ROTATE_MARGIN = 15.0  # move only when another candidate is clearly better (no flapping)
REGIONS = ("foreign", "ir")

WEIGHTS: Mapping[str, float] = {
    "reality": 15.0,
    "latency": 15.0,
    "dns": 35.0,
    "cert": 10.0,
    "vantage": 25.0,
}
DNS_FACTOR: Mapping[str, float] = {
    "own-domain": 1.0,
    "same-prefix": 0.7,
    "mismatch": 0.05,
    "unresolved": 0.0,
}

# Seeds only: everything is re-verified before use. "ir" names are for the Iran-side relay
# SNI (they must resolve to / plausibly cover the relay's domestic IP to survive #668).
SEED_CANDIDATES: Mapping[str, tuple[str, ...]] = {
    "foreign": sni_scout.DEFAULT_REALITY_CANDIDATES,
    "ir": (
        "www.digikala.com",
        "www.aparat.com",
        "divar.ir",
        "www.snapp.ir",
        "www.shaparak.ir",
        "www.irancell.ir",
    ),
}


@dataclass(frozen=True, slots=True)
class Observation:
    """One TLS check of a candidate from one vantage (network / ASN)."""

    vantage: str
    asn: int | None
    at: float
    ok: bool
    blocked: bool = False  # seen reset/blackholed on an Iranian network (not just slow)
    latency_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "vantage": self.vantage,
            "asn": self.asn,
            "at": self.at,
            "ok": self.ok,
            "blocked": self.blocked,
            "latency_ms": self.latency_ms,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Observation:
        asn = data.get("asn")
        lat = data.get("latency_ms")
        return cls(
            vantage=str(data["vantage"]),
            asn=int(asn) if asn is not None else None,
            at=float(data["at"]),
            ok=bool(data["ok"]),
            blocked=bool(data.get("blocked", False)),
            latency_ms=float(lat) if lat is not None else None,
        )


@dataclass(frozen=True, slots=True)
class Candidate:
    host: str
    region: str = "foreign"
    added_at: float = 0.0
    verified_at: float | None = None  # last successful TLS check from the exit
    tls_ok: bool = False
    tls_version: str | None = None
    alpn: str | None = None
    latency_ms: float | None = None
    cert_not_after: float | None = None
    dns_verdict: str | None = None  # sni_dns verdict against the node IP
    observations: tuple[Observation, ...] = ()
    detail: str = ""

    def __post_init__(self) -> None:
        validate_host(self.host, "sni bank host")
        if is_ip(self.host):
            raise ConfigError(f"an SNI candidate must be a domain name: {self.host!r}")
        if self.region not in REGIONS:
            raise ConfigError(f"region must be one of {REGIONS}: {self.region!r}")

    def expired(self, now: float, ttl_s: float = DEFAULT_TTL_S) -> bool:
        return self.verified_at is None or now - self.verified_at > ttl_s

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "region": self.region,
            "added_at": self.added_at,
            "verified_at": self.verified_at,
            "tls_ok": self.tls_ok,
            "tls_version": self.tls_version,
            "alpn": self.alpn,
            "latency_ms": self.latency_ms,
            "cert_not_after": self.cert_not_after,
            "dns_verdict": self.dns_verdict,
            "observations": [o.to_dict() for o in self.observations],
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Candidate:
        def opt(key: str) -> float | None:
            v = data.get(key)
            return float(v) if v is not None else None

        return cls(
            host=str(data["host"]),
            region=str(data.get("region", "foreign")),
            added_at=float(data.get("added_at", 0.0)),
            verified_at=opt("verified_at"),
            tls_ok=bool(data.get("tls_ok", False)),
            tls_version=data.get("tls_version"),
            alpn=data.get("alpn"),
            latency_ms=opt("latency_ms"),
            cert_not_after=opt("cert_not_after"),
            dns_verdict=data.get("dns_verdict"),
            observations=tuple(Observation.from_dict(o) for o in data.get("observations", ())),
            detail=str(data.get("detail", "")),
        )


@dataclass(frozen=True, slots=True)
class Score:
    host: str
    total: float
    factors: Mapping[str, float]
    expired: bool
    reasons: tuple[str, ...] = ()

    @property
    def usable(self) -> bool:
        return not self.expired and self.total >= MIN_PICK_SCORE


def _latency_factor(ms: float | None) -> float:
    if ms is None:
        return 0.0
    # <= 50 ms is perfect, 400 ms+ is worthless (REALITY waits for the target per connection)
    return max(0.0, min(1.0, (400.0 - ms) / 350.0))


def _cert_factor(not_after: float | None, now: float) -> float:
    if not_after is None:
        return 0.5
    days = (not_after - now) / 86400.0
    if days <= 3:
        return 0.0
    return min(1.0, days / 30.0)


def _vantage_factor(
    observations: Sequence[Observation], now: float, max_age_s: float
) -> tuple[float, list[str]]:
    fresh = [o for o in observations if now - o.at <= max_age_s]
    if not fresh:
        return 0.5, ["no fresh vantage reports"]  # unknown, neither good nor bad
    reasons: list[str] = []
    # newest observation per vantage wins
    latest: dict[str, Observation] = {}
    for o in sorted(fresh, key=lambda o: o.at):
        latest[o.vantage] = o
    blocked = [o for o in latest.values() if o.blocked]
    if blocked:
        names = ",".join(sorted(f"{o.vantage}/AS{o.asn}" for o in blocked))
        reasons.append(f"blocked on {names}")
        return 0.0, reasons
    share = sum(o.ok for o in latest.values()) / len(latest)
    if share < 1:
        reasons.append(f"passes on {share:.0%} of {len(latest)} vantages")
    return share, reasons


def score(
    cand: Candidate,
    now: float,
    *,
    ttl_s: float = DEFAULT_TTL_S,
    vantage_max_age_s: float = VANTAGE_MAX_AGE_S,
    strict_dns: bool = False,
) -> Score:
    """Score one candidate (0-100). ``strict_dns`` zeroes everything but an own domain."""
    expired = cand.expired(now, ttl_s)
    reasons: list[str] = ["not verified within TTL"] if expired else []
    if not cand.tls_ok:
        return Score(cand.host, 0.0, {"tls": 0.0}, expired, (*reasons, cand.detail or "tls failed"))
    factors: dict[str, float] = {"tls": 1.0}
    reality = 1.0
    if cand.alpn != "h2":
        reality -= 0.5
        reasons.append("no h2 ALPN")
    if cand.host.endswith(RISKY_TARGET_SUFFIXES):
        reality = 0.0
        reasons.append("risky suffix")
    factors["reality"] = reality
    factors["latency"] = _latency_factor(cand.latency_ms)
    dns = DNS_FACTOR.get(cand.dns_verdict or "", 0.3)  # unknown node IP: neutral-low
    if cand.dns_verdict is None:
        reasons.append("DNS vs node IP not checked")
    elif cand.dns_verdict == "mismatch":
        reasons.append("SNI does not resolve near the node IP (mismatch DPI)")
    if strict_dns and cand.dns_verdict != "own-domain":
        dns = 0.0
    factors["dns"] = dns
    factors["cert"] = _cert_factor(cand.cert_not_after, now)
    if factors["cert"] == 0.0:
        reasons.append("certificate expires within 3 days")
    vf, vreasons = _vantage_factor(cand.observations, now, vantage_max_age_s)
    factors["vantage"] = vf
    reasons += vreasons
    total = sum(WEIGHTS[k] * factors[k] for k in WEIGHTS)
    if vf == 0.0 and any(o.blocked for o in cand.observations):
        total = min(total, 10.0)  # a block sighting beats every other virtue
    return Score(cand.host, round(total, 1), factors, expired, tuple(reasons))


@dataclass(frozen=True, slots=True)
class SniBank:
    candidates: tuple[Candidate, ...] = ()
    node_ip: str | None = None
    active: Mapping[str, str] = field(default_factory=dict)  # region -> host in use

    def get(self, host: str) -> Candidate | None:
        return next((c for c in self.candidates if c.host == host), None)

    def upsert(self, cand: Candidate) -> SniBank:
        rest = tuple(c for c in self.candidates if c.host != cand.host)
        return replace(self, candidates=(*rest, cand))

    def add(self, hosts: Iterable[str], region: str, now: float) -> SniBank:
        bank = self
        for host in hosts:
            if bank.get(host) is None:
                bank = bank.upsert(Candidate(host, region=region, added_at=now))
        return bank

    def ranked(self, now: float, *, region: str | None = None, **kw: Any) -> list[Score]:
        pool = [c for c in self.candidates if region is None or c.region == region]
        scores = [score(c, now, **kw) for c in pool]
        return sorted(scores, key=lambda s: (not s.usable, -s.total, s.host))

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": BANK_VERSION,
            "node_ip": self.node_ip,
            "active": dict(self.active),
            "candidates": [c.to_dict() for c in sorted(self.candidates, key=lambda c: c.host)],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SniBank:
        if data.get("version") != BANK_VERSION:
            raise ConfigError(f"unsupported sni bank version: {data.get('version')!r}")
        return cls(
            candidates=tuple(Candidate.from_dict(c) for c in data.get("candidates", ())),
            node_ip=data.get("node_ip"),
            active={str(k): str(v) for k, v in dict(data.get("active", {})).items()},
        )


def load_bank(path: Path) -> SniBank:
    if not path.exists():
        return SniBank()
    try:
        return SniBank.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (ValueError, KeyError, TypeError) as exc:
        raise ConfigError(f"invalid sni bank {path}: {exc}") from exc


def save_bank(path: Path, bank: SniBank) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".sni-bank-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(bank.to_dict(), fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


# --- verification (network through sni_scout) ------------------------------------------------

Handshake = Callable[[str, int, float], sni_scout.ScoutResult]


def apply_check(
    cand: Candidate,
    result: sni_scout.ScoutResult,
    now: float,
    dns: sni_dns.SniDnsCheck | None = None,
) -> Candidate:
    """Fold one exit-side TLS check (and optional DNS verdict) into a candidate."""
    return replace(
        cand,
        verified_at=now if result.ok else cand.verified_at,
        tls_ok=result.ok,
        tls_version=result.tls_version,
        alpn=result.alpn,
        latency_ms=result.latency_ms,
        cert_not_after=result.cert_not_after,
        dns_verdict=str(dns.verdict) if dns is not None else cand.dns_verdict,
        detail=result.detail,
    )


def refresh(
    bank: SniBank,
    now: float | None = None,
    *,
    only_due: bool = True,
    ttl_s: float = DEFAULT_TTL_S,
    timeout_s: float = sni_scout.DEFAULT_TIMEOUT_S,
    handshake: Handshake | None = None,
    resolver: sni_dns.Resolver = sni_dns.system_resolver,
) -> SniBank:
    """Re-verify candidates (all, or only expired/near-expiry ones) from this vantage."""
    now = time.time() if now is None else now
    shake = handshake or sni_scout._handshake
    for cand in bank.candidates:
        if only_due and not cand.expired(now, ttl_s * 0.75):
            continue
        result = shake(cand.host, 443, timeout_s)
        dns = sni_dns.check(cand.host, bank.node_ip, resolver) if bank.node_ip else None
        bank = bank.upsert(apply_check(cand, result, now, dns))
    return bank


# --- multi-vantage hook ----------------------------------------------------------------------


def merge_vantage_report(
    bank: SniBank, report: Mapping[str, Any], *, now: float, max_age_s: float = VANTAGE_MAX_AGE_S
) -> SniBank:
    """Fold a vantage's SNI report into the bank.

    Format (same spirit as ``vantage.py``; hostnames and booleans only)::

        {"version": 1, "vantage": "ir-mci", "asn": 197207, "generated_at": 1700000000.0,
         "sni": {"www.example.com": {"ok": true, "latency_ms": 41.0},
                 "blocked.example": {"ok": false, "blocked": true}}}

    A report older than ``max_age_s`` is ignored; unknown hosts are not added (the bank owner
    decides what to probe).
    """
    if report.get("version") != 1:
        raise ConfigError("unsupported vantage sni report version")
    vantage = str(report.get("vantage") or "")
    if not vantage:
        raise ConfigError("vantage sni report needs a vantage name")
    generated = float(report.get("generated_at", 0.0))
    if now - generated > max_age_s:
        return bank
    asn_raw = report.get("asn")
    asn = int(asn_raw) if asn_raw is not None else None
    for host, row in dict(report.get("sni", {})).items():
        cand = bank.get(str(host))
        if cand is None or not isinstance(row, Mapping):
            continue
        lat = row.get("latency_ms")
        obs = Observation(
            vantage=vantage,
            asn=asn,
            at=generated,
            ok=bool(row.get("ok", False)),
            blocked=bool(row.get("blocked", False)),
            latency_ms=float(lat) if lat is not None else None,
        )
        kept = (*tuple(o for o in cand.observations if o.vantage != vantage), obs)
        bank = bank.upsert(replace(cand, observations=kept))
    return bank


def build_vantage_report(
    results: Sequence[sni_scout.ScoutResult], *, vantage: str, asn: int | None, now: float
) -> dict[str, Any]:
    """A report from this vantage's scout results ("blocked" = reset/timeout, not a cert error)."""
    sni: dict[str, dict[str, Any]] = {}
    for r in results:
        blocked = not r.ok and any(
            k in r.detail for k in ("ConnectionResetError", "TimeoutError", "timed out")
        )
        sni[r.host] = {"ok": r.ok, "blocked": blocked, "latency_ms": r.latency_ms}
    return {"version": 1, "vantage": vantage, "asn": asn, "generated_at": now, "sni": sni}


# --- selection / rotation --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Rotation:
    region: str
    current: str | None
    pick: str | None
    rotate: bool
    reason: str


def rotation(bank: SniBank, region: str, now: float, **kw: Any) -> Rotation:
    """Should the active SNI of ``region`` move, and to what?

    Rotate when the current one expired (not re-verified within TTL), fell below
    ``MIN_PICK_SCORE`` (e.g. a block sighting), or another candidate beats it by
    ``ROTATE_MARGIN``. Never picks an expired or unusable candidate.
    """
    ranked = bank.ranked(now, region=region, **kw)
    best = next((s for s in ranked if s.usable), None)
    current = bank.active.get(region)
    cur = next((s for s in ranked if s.host == current), None)
    if best is None:
        return Rotation(region, current, None, False, "no usable candidate: refresh the bank")
    if cur is None:
        return Rotation(region, current, best.host, True, "no active SNI")
    if cur.expired:
        return Rotation(region, current, best.host, best.host != current, "active SNI expired")
    if not cur.usable:
        why = "; ".join(cur.reasons) or f"score {cur.total}"
        return Rotation(region, current, best.host, best.host != current, f"active unusable: {why}")
    if best.host != current and best.total >= cur.total + ROTATE_MARGIN:
        return Rotation(
            region, current, best.host, True, f"{best.host} scores {best.total} vs {cur.total}"
        )
    return Rotation(region, current, current, False, f"keep (score {cur.total})")


def activate(bank: SniBank, region: str, host: str) -> SniBank:
    if bank.get(host) is None:
        raise ConfigError(f"{host!r} is not in the bank")
    return replace(bank, active={**bank.active, region: host})


def passing_snis(
    bank: SniBank, asn: int, now: float, max_age_s: float = VANTAGE_MAX_AGE_S
) -> tuple[str, ...]:
    """Candidates a fresh report from ``asn`` saw pass, best score first (for tactics)."""
    good = []
    for cand in bank.candidates:
        obs = [o for o in cand.observations if o.asn == asn and now - o.at <= max_age_s]
        if obs and max(obs, key=lambda o: o.at).ok and not cand.expired(now):
            good.append((score(cand, now).total, cand.host))
    return tuple(h for _, h in sorted(good, key=lambda t: (-t[0], t[1])))
