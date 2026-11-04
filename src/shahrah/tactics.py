"""Per-network anti-censorship tactics (Psiphon-style), signed and delivered with subscriptions.

Iran does not filter uniformly: what survives on one ISP/ASN (e.g. a mobile carrier under an
allowlist regime, net4people/bbs#630) can be dead on another. A *tactics profile* says, for a
given ASN and Oracle mode, which transports to prefer, in which port order, which SNIs are
known to pass the allowlist there, which domestic-hosted entry hosts to use, and whether the
raw-packet crisis path (paqet) should be enabled.

Profiles travel in a :class:`TacticsBundle`, wrapped in an HMAC-SHA256 envelope. The standard
library has no Ed25519, so the signature is symmetric: it proves the bundle came from someone
holding the key and was not altered or replayed after expiry; it is *not* public-key signing.
Clients that will verify bundles need the key (or a per-client derived key) - see
docs/ALLOWLIST.md. Nothing here touches the network.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from enum import StrEnum
from typing import Any

from . import sni_bank
from .models import CRISIS_PORTS, ConfigError, Endpoint, validate_host, validate_port
from .oracle import Mode

ENVELOPE_VERSION = 1
MIN_KEY_BYTES = 32


class Transport(StrEnum):
    REALITY_VISION = "reality-vision"
    REALITY_XHTTP = "reality-xhttp"
    CDN_XHTTP = "cdn-xhttp"
    DOMESTIC_RELAY = "domestic-relay"  # entry on an Iran-hosted server, backhauled abroad
    PAQET = "paqet"  # raw-packet KCP crisis path (bbs#570); needs root on the client side


@dataclass(frozen=True, slots=True)
class TacticsProfile:
    name: str
    mode: Mode
    asns: tuple[int, ...] = ()  # empty: default for every network
    transports: tuple[Transport, ...] = (Transport.REALITY_VISION, Transport.REALITY_XHTTP)
    ports: tuple[int, ...] = CRISIS_PORTS
    sni_allowlist: tuple[str, ...] = ()  # SNIs observed to pass on this network
    entry_hosts: tuple[str, ...] = ()  # domestic-hosted entries used while restricted
    paqet: bool = False
    fragment: bool = False  # ClientHello fragmentation; dead in Iran per bbs#640, opt-in only

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ConfigError("tactics profile needs a name")
        if not self.transports:
            raise ConfigError(f"tactics {self.name!r}: at least one transport is required")
        if len(set(self.transports)) != len(self.transports):
            raise ConfigError(f"tactics {self.name!r}: duplicate transports")
        if not self.ports or len(set(self.ports)) != len(self.ports):
            raise ConfigError(f"tactics {self.name!r}: ports must be non-empty and unique")
        for port in self.ports:
            validate_port(port, "tactics port")
        for asn in self.asns:
            if not isinstance(asn, int) or isinstance(asn, bool) or not 0 < asn < 2**32:
                raise ConfigError(f"tactics {self.name!r}: invalid ASN {asn!r}")
        for host in (*self.sni_allowlist, *self.entry_hosts):
            validate_host(host, "tactics host")
        if self.paqet and Transport.PAQET not in self.transports:
            raise ConfigError(f"tactics {self.name!r}: paqet=True needs the paqet transport")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["mode"] = str(self.mode)
        data["transports"] = [str(t) for t in self.transports]
        for key in ("asns", "ports", "sni_allowlist", "entry_hosts"):
            data[key] = list(data[key])
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TacticsProfile:
        try:
            return cls(
                name=str(data["name"]),
                mode=Mode(data["mode"]),
                asns=tuple(int(a) for a in data.get("asns", ())),
                transports=tuple(Transport(t) for t in data["transports"]),
                ports=tuple(int(p) for p in data.get("ports", CRISIS_PORTS)),
                sni_allowlist=tuple(data.get("sni_allowlist", ())),
                entry_hosts=tuple(data.get("entry_hosts", ())),
                paqet=bool(data.get("paqet", False)),
                fragment=bool(data.get("fragment", False)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, ConfigError):
                raise
            raise ConfigError(f"invalid tactics profile: {exc}") from exc


# Built-in fallbacks when no network-specific profile matches.
DEFAULT_PROFILES: tuple[TacticsProfile, ...] = (
    TacticsProfile("default-normal", Mode.NORMAL),
    TacticsProfile(
        "default-degraded",
        Mode.DEGRADED,
        transports=(Transport.REALITY_VISION, Transport.REALITY_XHTTP, Transport.CDN_XHTTP),
    ),
    TacticsProfile(
        "default-restricted",
        Mode.RESTRICTED,
        transports=(
            Transport.DOMESTIC_RELAY,
            Transport.REALITY_XHTTP,
            Transport.CDN_XHTTP,
            Transport.PAQET,
        ),
        paqet=True,
    ),
    TacticsProfile(
        "default-outage",
        Mode.OUTAGE,
        transports=(Transport.DOMESTIC_RELAY, Transport.PAQET, Transport.CDN_XHTTP),
        paqet=True,
    ),
)


def select(
    profiles: Iterable[TacticsProfile], mode: Mode, asn: int | None = None
) -> TacticsProfile:
    """ASN-specific profile for ``mode`` if any, else the generic one, else the built-in."""
    candidates = [p for p in profiles if p.mode is mode]
    if asn is not None:
        for profile in candidates:
            if asn in profile.asns:
                return profile
    for profile in candidates:
        if not profile.asns:
            return profile
    for profile in DEFAULT_PROFILES:
        if profile.mode is mode:
            return profile
    raise ConfigError(f"no tactics for mode {mode}")  # pragma: no cover - defaults cover all


_PROFILE_TO_TRANSPORT = {
    "reality-vision": Transport.REALITY_VISION,
    "reality-xhttp": Transport.REALITY_XHTTP,
    "cdn-xhttp": Transport.CDN_XHTTP,
}


def order_endpoints(endpoints: Sequence[Endpoint], profile: TacticsProfile) -> list[Endpoint]:
    """Order endpoints by the profile: transport preference, then port order, then priority.

    Endpoints whose transport is not in the profile are dropped; endpoints on a host listed in
    ``entry_hosts`` count as :attr:`Transport.DOMESTIC_RELAY`.
    """
    entry = set(profile.entry_hosts)
    rank_t = {t: i for i, t in enumerate(profile.transports)}
    rank_p = {p: i for i, p in enumerate(profile.ports)}
    scored: list[tuple[tuple[int, int, int, str], Endpoint]] = []
    for endpoint in endpoints:
        transport = (
            Transport.DOMESTIC_RELAY
            if endpoint.host in entry
            else _PROFILE_TO_TRANSPORT[str(endpoint.profile)]
        )
        if transport not in rank_t:
            continue
        key = (
            rank_t[transport],
            rank_p.get(endpoint.port, len(rank_p)),
            endpoint.priority,
            endpoint.name,
        )
        scored.append((key, endpoint))
    return [endpoint for _, endpoint in sorted(scored, key=lambda item: item[0])]


@dataclass(frozen=True, slots=True)
class TacticsBundle:
    serial: int  # monotonically increasing; clients refuse anything older than they hold
    issued_at: int
    expires_at: int
    profiles: tuple[TacticsProfile, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.serial < 1:
            raise ConfigError("bundle serial must be >= 1")
        if self.expires_at <= self.issued_at:
            raise ConfigError("bundle must expire after it is issued")
        names = [p.name for p in self.profiles]
        if len(set(names)) != len(names):
            raise ConfigError("tactics profile names must be unique within a bundle")

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "profiles": [p.to_dict() for p in self.profiles],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TacticsBundle:
        try:
            return cls(
                serial=int(data["serial"]),
                issued_at=int(data["issued_at"]),
                expires_at=int(data["expires_at"]),
                profiles=tuple(TacticsProfile.from_dict(p) for p in data.get("profiles", ())),
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, ConfigError):
                raise
            raise ConfigError(f"invalid tactics bundle: {exc}") from exc


def _canonical(data: Mapping[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _mac(key: bytes, key_id: str, payload: str) -> str:
    message = f"shahrah-tactics/{ENVELOPE_VERSION}/{key_id}/{payload}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def sign(bundle: TacticsBundle, key: bytes, key_id: str) -> dict[str, Any]:
    """Return a JSON-serialisable signed envelope."""
    if len(key) < MIN_KEY_BYTES:
        raise ConfigError(f"tactics key must be at least {MIN_KEY_BYTES} bytes")
    if not key_id or "/" in key_id:
        raise ConfigError("key_id must be non-empty and contain no '/'")
    payload = _b64(_canonical(bundle.to_dict()))
    return {
        "v": ENVELOPE_VERSION,
        "kid": key_id,
        "payload": payload,
        "sig": _mac(key, key_id, payload),
    }


def verify(
    envelope: Mapping[str, Any],
    keys: Mapping[str, bytes],
    *,
    now: float,
    min_serial: int = 0,
) -> TacticsBundle:
    """Check signature, expiry and replay; return the bundle or raise :class:`ConfigError`."""
    try:
        version, key_id = envelope["v"], str(envelope["kid"])
        payload, sig = str(envelope["payload"]), str(envelope["sig"])
    except (KeyError, TypeError) as exc:
        raise ConfigError(f"malformed tactics envelope: {exc}") from exc
    if version != ENVELOPE_VERSION:
        raise ConfigError(f"unsupported tactics envelope version {version!r}")
    key = keys.get(key_id)
    if key is None:
        raise ConfigError(f"unknown tactics key id {key_id!r}")
    if not hmac.compare_digest(_mac(key, key_id, payload), sig):
        raise ConfigError("tactics signature mismatch")
    try:
        data = json.loads(_unb64(payload))
    except (ValueError, UnicodeError) as exc:
        raise ConfigError(f"tactics payload is not valid JSON: {exc}") from exc
    bundle = TacticsBundle.from_dict(data)
    if now >= bundle.expires_at:
        raise ConfigError("tactics bundle has expired")
    if now < bundle.issued_at - 300:
        raise ConfigError("tactics bundle is issued in the future")
    if bundle.serial < min_serial:
        raise ConfigError("tactics bundle is older than the one already held (replay)")
    return bundle


def with_bank_snis(profile: TacticsProfile, bank: sni_bank.SniBank, now: float) -> TacticsProfile:
    """Refresh ``sni_allowlist`` from fresh per-ASN vantage reports in the SNI bank.

    Names the bank saw pass on the profile's ASNs come first (best score first), followed by
    any operator-pinned names that were not seen blocked. A profile without ASNs is left as is.
    """
    if not profile.asns:
        return profile
    seen: list[str] = []
    for asn in profile.asns:
        for host in sni_bank.passing_snis(bank, asn, now):
            if host not in seen:
                seen.append(host)
    for host in profile.sni_allowlist:
        cand = bank.get(host)
        blocked = cand is not None and any(
            o.blocked and o.asn in profile.asns for o in cand.observations
        )
        if host not in seen and not blocked:
            seen.append(host)
    return replace(profile, sni_allowlist=tuple(seen))
