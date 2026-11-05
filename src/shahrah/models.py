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
    # VLESS over plain XHTTP behind a CDN / TLS reverse proxy that terminates TLS: the crisis
    # layer, reachable through a CDN edge when direct server IPs are blocked.
    CDN_XHTTP = "cdn-xhttp"


XHTTP_MODES = frozenset({"auto", "packet-up", "stream-up", "stream-one"})
# CDNs buffer or cut long single-request streams, so stream-one is refused behind a CDN.
CDN_XHTTP_MODES = frozenset({"auto", "packet-up", "stream-up"})
# Plain HTTP between the CDN and the origin is only protected by an unguessable path.
MIN_CDN_PATH_LENGTH = 9

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
    # Social-quality knobs (Xray docs: config/transports/sockopt.md, config/policy.md). All
    # default to "not emitted" so the default config is byte-identical to before.
    tcp_fast_open: bool = False  # sockopt.tcpFastOpen; kernel side: tcp_fastopen=3 (sysctl)
    tcp_congestion: str = ""  # sockopt.tcpcongestion (Linux); docs recommend bbr
    tcp_user_timeout_ms: int = 0  # sockopt.tcpUserTimeout; 0 = OS default
    uplink_only_s: int | None = None  # policy.uplinkOnly; docs: 0 helps HTTP browsing
    downlink_only_s: int | None = None  # policy.downlinkOnly

    def __post_init__(self) -> None:
        if self.tcp_congestion not in {"", "bbr", "cubic", "reno"}:
            raise ConfigError(f"tcp_congestion must be bbr/cubic/reno: {self.tcp_congestion!r}")
        if self.tcp_user_timeout_ms != 0 and not 1000 <= self.tcp_user_timeout_ms <= 120000:
            raise ConfigError("tcp_user_timeout_ms must be 0 or 1000..120000")
        for name in ("uplink_only_s", "downlink_only_s"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, int) or not 0 <= value <= 30):
                raise ConfigError(f"{name} must be None or an integer in 0..30")
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


# Named tuning presets. "social" favours many short, latency-sensitive flows (Instagram feed,
# image/video thumbnails, DMs) over bulk throughput; every knob is documented by Xray:
# * uplinkOnly/downlinkOnly 0: policy.md says 0 "improves connection closing efficiency" for
#   HTTP browsing, freeing slots quickly when apps open and close many requests;
# * tcpFastOpen: saves one RTT on repeat connects where both sides support TFO;
# * tcpcongestion bbr: sockopt.md's recommendation; tolerant of lossy international links;
# * tcpUserTimeout 10 s (the docs' example): drop flows whose peer vanished (mobile handover)
#   instead of letting them stall until keepalive gives up.
TUNING_PROFILES: dict[str, Tuning] = {
    "default": Tuning(),
    "social": Tuning(
        tcp_fast_open=True,
        tcp_congestion="bbr",
        tcp_user_timeout_ms=10000,
        uplink_only_s=0,
        downlink_only_s=0,
    ),
}


# Ports that stay reachable when Iran drops to an allowlist-style shutdown (TCP only).
CRISIS_PORTS = (443, 80, 53)


@dataclass(frozen=True, slots=True)
class Listener:
    """One public inbound: a port plus how it carries traffic.

    For ``CDN_XHTTP`` the listener speaks plain XHTTP (no TLS of its own); ``cdn_host`` is the
    domain clients dial (the CDN edge) and ``edge_tls`` says whether clients use TLS to it.
    """

    port: int
    profile: Profile
    xhttp_path: str = "/shahrah"
    xhttp_mode: str = "stream-one"
    cdn_host: str = ""
    edge_tls: bool = True
    edge_port: int = 0  # 0 = 443 (TLS) or 80 (plain); CF-compatible alt e.g. 2053

    def __post_init__(self) -> None:
        validate_port(self.port)
        _validate_xhttp(self.xhttp_path, self.xhttp_mode)
        if self.profile is Profile.REALITY_XHTTP and self.xhttp_path == "/":
            raise ConfigError(
                "xhttp_path '/' collides with the REALITY/cover site root and stalls the "
                "stream; use a dedicated path such as /shahrah"
            )
        if self.profile is Profile.CDN_XHTTP:
            if not self.cdn_host or is_ip(self.cdn_host):
                raise ConfigError("a cdn-xhttp listener needs cdn_host set to a domain name")
            validate_host(self.cdn_host, "cdn host")
            if self.xhttp_mode not in CDN_XHTTP_MODES:
                raise ConfigError(
                    f"xhttp mode behind a CDN must be one of {sorted(CDN_XHTTP_MODES)}: "
                    f"{self.xhttp_mode!r}"
                )
            if len(self.xhttp_path) < MIN_CDN_PATH_LENGTH:
                raise ConfigError(
                    "a cdn-xhttp path must be unguessable (at least "
                    f"{MIN_CDN_PATH_LENGTH} characters): the origin speaks plain HTTP"
                )
            if self.edge_port:
                validate_port(self.edge_port, "cdn edge port")
        elif self.cdn_host:
            raise ConfigError("cdn_host is only valid for cdn-xhttp listeners")
        elif self.edge_port:
            raise ConfigError("edge_port is only valid for cdn-xhttp listeners")


@dataclass(frozen=True, slots=True)
class ServerSettings:
    """One Xray server: a primary listener plus optional extra ones on other ports.

    All listeners share the same REALITY identity. Offering 443 together with 80 and 53 lets
    a client fall over to whichever port the censor still lets through.
    """

    profile: Profile
    reality: RealityServer
    listen: str = "0.0.0.0"  # noqa: S104 - a public VPN server must listen on all interfaces
    port: int = 443
    xhttp_path: str = "/shahrah"
    xhttp_mode: str = "stream-one"
    allow_non_443: bool = False  # permit ports outside CRISIS_PORTS (443/80/53)
    stats_api_port: int | None = None  # loopback-only gRPC stats API for usage accounting
    # Opt-in: when set, Xray writes an access log (needed by SNI watch). Default is off so a
    # seized server does not contain a browsing history.
    access_log: str | None = None
    tuning: Tuning = field(default_factory=Tuning)
    extra_listeners: tuple[Listener, ...] = ()

    def __post_init__(self) -> None:
        validate_port(self.port)
        _validate_xhttp(self.xhttp_path, self.xhttp_mode)
        if self.profile is Profile.REALITY_XHTTP and self.xhttp_path == "/":
            raise ConfigError(
                "xhttp_path '/' collides with the REALITY cover site root and stalls the "
                "stream; use a dedicated path such as /shahrah"
            )
        if self.profile is Profile.CDN_XHTTP:
            raise ConfigError("the primary listener must be a REALITY profile")
        if self.access_log is not None and (
            not self.access_log.startswith("/") or any(ch.isspace() for ch in self.access_log)
        ):
            raise ConfigError("access_log must be an absolute path without whitespace")
        listeners = self.listeners()
        ports = [listener.port for listener in listeners]
        if len(set(ports)) != len(ports):
            raise ConfigError(f"listener ports must be unique: {ports}")
        for port in ports:
            if port not in CRISIS_PORTS and not self.allow_non_443:
                raise ConfigError(
                    f"port {port} is not one of {CRISIS_PORTS}, the TCP ports that survive "
                    "allowlist shutdowns; set allow_non_443=True to override"
                )
        if self.stats_api_port is not None:
            validate_port(self.stats_api_port, "stats api port")
            if self.stats_api_port in ports:
                raise ConfigError("stats api port must differ from the public ports")

    def listeners(self) -> tuple[Listener, ...]:
        primary = Listener(self.port, self.profile, self.xhttp_path, self.xhttp_mode)
        return (primary, *self.extra_listeners)


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
    public_key: str = ""  # REALITY profiles only
    short_id: str = ""  # REALITY profiles only
    sni: str = ""  # REALITY: handshake target; CDN: TLS server name
    tls: bool = True  # CDN profile only: does the client use TLS to the edge?
    fingerprint: str = "chrome"
    xhttp_path: str = "/shahrah"
    xhttp_mode: str = "stream-one"
    priority: int = 0
    lockdown_capable: bool = False

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ConfigError("endpoint name must not be empty")
        validate_host(self.host, "endpoint host")
        validate_port(self.port, "endpoint port")
        _validate_xhttp(self.xhttp_path, self.xhttp_mode)
        if self.profile is Profile.CDN_XHTTP:
            if self.public_key or self.short_id:
                raise ConfigError("a cdn-xhttp endpoint has no REALITY key or short id")
            if self.tls:
                validate_host(self.sni, "endpoint sni")
            elif self.sni:
                raise ConfigError("sni must be empty when the edge is reached without TLS")
            if self.xhttp_mode not in CDN_XHTTP_MODES:
                raise ConfigError(f"xhttp mode behind a CDN must not be {self.xhttp_mode!r}")
            return
        validate_x25519_key(self.public_key, "REALITY public key")
        validate_short_id(self.short_id)
        validate_host(self.sni, "endpoint sni")
