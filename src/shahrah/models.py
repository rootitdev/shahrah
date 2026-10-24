"""Typed, validated domain models.

Pure data: no I/O and no hardcoded infrastructure (hosts, IPs, keys). Every value that
could identify a deployment is passed in by the caller, so the project stays publishable.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import dataclass, field
from enum import StrEnum


class ConfigError(ValueError):
    """Raised when a model is built from invalid or unsafe values."""


class Profile(StrEnum):
    """How a client reaches a server. One profile per listening port."""

    REALITY_VISION = "reality-vision"  # VLESS + REALITY + XTLS-Vision over raw TCP
    REALITY_XHTTP = "reality-xhttp"  # VLESS + REALITY over XHTTP


XHTTP_MODES = frozenset({"auto", "packet-up", "stream-up", "stream-one"})

# Borrowing an Apple/iCloud handshake target gets server IPs blocked quickly
# (also warned about by Xray itself), so it is refused by default.
RISKY_TARGET_SUFFIXES = ("apple.com", "icloud.com", "mzstatic.com")

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_SHORT_ID_RE = re.compile(r"^(?:[0-9a-f]{2}){1,8}$")
_X25519_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")


def is_ip(value: str) -> bool:
    """Return True when ``value`` is an IPv4 or IPv6 literal."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def validate_host(value: str, what: str = "host") -> str:
    """Accept a lowercase DNS name or an IP literal; reject everything else."""
    if is_ip(value) or _DOMAIN_RE.fullmatch(value):
        return value
    raise ConfigError(f"{what} must be a lowercase domain name or an IP address: {value!r}")


def validate_port(value: int, what: str = "port") -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise ConfigError(f"{what} must be an integer in 1..65535: {value!r}")
    return value


def validate_short_id(value: str) -> str:
    if not _SHORT_ID_RE.fullmatch(value):
        raise ConfigError("REALITY short id must be 2-16 lowercase hex characters (even length)")
    return value


def validate_x25519_key(value: str, what: str) -> str:
    if not _X25519_KEY_RE.fullmatch(value):
        raise ConfigError(f"{what} must be a 43-character base64url X25519 key")
    return value


def _validate_xhttp(path: str, mode: str) -> None:
    if not path.startswith("/"):
        raise ConfigError(f"xhttp path must start with '/': {path!r}")
    if mode not in XHTTP_MODES:
        raise ConfigError(f"xhttp mode must be one of {sorted(XHTTP_MODES)}: {mode!r}")


@dataclass(frozen=True, slots=True)
class RealityServer:
    """Server-side REALITY parameters (contains the private key)."""

    target_host: str
    private_key: str
    short_ids: tuple[str, ...]
    server_names: tuple[str, ...] = ()
    target_port: int = 443
    # Newer Xray builds may reject older clients when this is unset; "1.0.0" accepts all.
    min_client_ver: str = "1.0.0"
    allow_risky_target: bool = False

    def __post_init__(self) -> None:
        validate_host(self.target_host, "REALITY target host")
        if is_ip(self.target_host):
            raise ConfigError("REALITY target must be a domain name, not an IP address")
        validate_port(self.target_port, "REALITY target port")
        validate_x25519_key(self.private_key, "REALITY private key")
        if not self.short_ids:
            raise ConfigError("at least one REALITY short id is required")
        for short_id in self.short_ids:
            validate_short_id(short_id)
        names = self.server_names or (self.target_host,)
        for name in names:
            validate_host(name, "REALITY server name")
        object.__setattr__(self, "server_names", tuple(names))
        risky = self.target_host.endswith(RISKY_TARGET_SUFFIXES)
        if risky and not self.allow_risky_target:
            raise ConfigError(
                f"REALITY target {self.target_host!r} is known to get server IPs blocked; "
                "pick another TLS 1.3 site or set allow_risky_target=True"
            )


@dataclass(frozen=True, slots=True)
class Tuning:
    """Stability knobs. Defaults suit ~1-3k users on one mid-size VPS; tune after load tests.

    * ``dns_servers`` - the server resolves every destination itself, over DoH by default,
      so names are never resolved through the VPS provider's (possibly poisoned) resolver.
    * ``conn_idle_s`` / ``handshake_s`` - reap stalled connections instead of letting them pile up.
    * ``buffer_size_kb`` - per-connection buffer. Xray's own default is large on x86, which
      multiplies badly across tens of thousands of connections.
    * ``tcp_keepalive_*`` - detect clients that vanished (mobile networks switching) so no
      half-open "dead" connections linger.
    """

    dns_servers: tuple[str, ...] = (
        "https+local://1.1.1.1/dns-query",
        "https+local://8.8.8.8/dns-query",
    )
    conn_idle_s: int = 300
    handshake_s: int = 4
    buffer_size_kb: int = 128
    tcp_keepalive_idle_s: int = 30
    tcp_keepalive_interval_s: int = 15

    def __post_init__(self) -> None:
        if not self.dns_servers:
            raise ConfigError("at least one DNS server is required")
        for server in self.dns_servers:
            if not server or any(ch.isspace() for ch in server):
                raise ConfigError(f"invalid DNS server entry: {server!r}")
        bounds = {
            "conn_idle_s": (30, 3600),
            "handshake_s": (2, 30),
            "buffer_size_kb": (4, 2048),
            "tcp_keepalive_idle_s": (5, 600),
            "tcp_keepalive_interval_s": (1, 300),
        }
        for name, (low, high) in bounds.items():
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
                raise ConfigError(f"{name} must be an integer in {low}..{high}: {value!r}")


@dataclass(frozen=True, slots=True)
class ServerSettings:
    """One Xray server: which profile it serves and on which port."""

    profile: Profile
    reality: RealityServer
    listen: str = "0.0.0.0"  # noqa: S104 - a public VPN server must listen on all interfaces
    port: int = 443
    xhttp_path: str = "/"
    xhttp_mode: str = "stream-one"
    allow_non_443: bool = False
    stats_api_port: int | None = None  # loopback-only gRPC stats API for usage accounting
    tuning: Tuning = field(default_factory=Tuning)

    def __post_init__(self) -> None:
        validate_port(self.port)
        if self.port != 443 and not self.allow_non_443:
            raise ConfigError(
                "only TCP/443 reliably survives allowlist shutdowns; "
                "set allow_non_443=True to override"
            )
        _validate_xhttp(self.xhttp_path, self.xhttp_mode)
        if self.stats_api_port is not None:
            validate_port(self.stats_api_port, "stats api port")
            if self.stats_api_port == self.port:
                raise ConfigError("stats api port must differ from the public port")


@dataclass(frozen=True, slots=True)
class User:
    """A VPN account. ``label`` is an opaque id used for usage stats, never personal data."""

    uuid: str
    label: str

    def __post_init__(self) -> None:
        try:
            canonical = str(uuid.UUID(self.uuid))
        except ValueError as exc:
            raise ConfigError(f"invalid user uuid: {self.uuid!r}") from exc
        object.__setattr__(self, "uuid", canonical)
        if not _LABEL_RE.fullmatch(self.label):
            raise ConfigError(f"user label must match {_LABEL_RE.pattern}: {self.label!r}")

    @classmethod
    def create(cls, label: str) -> User:
        return cls(uuid=str(uuid.uuid4()), label=label)


@dataclass(frozen=True, slots=True)
class Endpoint:
    """What a client connects to (public data only: never contains a private key)."""

    name: str
    host: str
    port: int
    profile: Profile
    public_key: str
    short_id: str
    sni: str
    fingerprint: str = "chrome"
    xhttp_path: str = "/"
    xhttp_mode: str = "stream-one"
    priority: int = 0
    lockdown_capable: bool = False

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ConfigError("endpoint name must not be empty")
        validate_host(self.host, "endpoint host")
        validate_port(self.port, "endpoint port")
        validate_x25519_key(self.public_key, "REALITY public key")
        validate_short_id(self.short_id)
        validate_host(self.sni, "endpoint sni")
        _validate_xhttp(self.xhttp_path, self.xhttp_mode)
