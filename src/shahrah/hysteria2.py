"""Hysteria2: QUIC/UDP data plane for social traffic (external, pinned binary).

`Hysteria <https://github.com/apernet/hysteria>`_ (MIT licence, Go) is a QUIC proxy with its
own congestion control ("Brutal") and Salamander obfuscation, which makes every packet look
like random UDP instead of recognisable QUIC/HTTP-3. Shahrah never vendors Hysteria code: it
renders YAML configs (JSON scalars are valid YAML), emits share links and port-hopping
firewall rules, pins the release checksum, and probes the path through a local SOCKS client.

Why it is a separate path and not a replacement for REALITY:

* UDP is the first thing Iranian networks throttle or drop in an allowlist regime, so this path
  is ``lockdown_capable=False`` and the Oracle ranks REALITY/TCP above it by default;
* where UDP *is* open, QUIC avoids TCP head-of-line blocking, which is exactly what an
  Instagram feed (dozens of parallel small image/video requests) suffers from on lossy mobile
  links. The "social" preset therefore keeps receive windows modest (less bufferbloat, faster
  first byte) and declares moderate bandwidth instead of saturating the link.

Certificates: Hysteria needs real TLS. With a self-signed certificate clients must pin it.
``pinSHA256`` is the SHA-256 of the *leaf certificate DER* (``openssl x509 -fingerprint
-sha256``), NOT of the SPKI/public key - mixing the two was a recurring failure in the ops logs
(see docs/DIAG_LESSONS.md), so :func:`cert_pin` computes it from the PEM directly.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import socket
import subprocess
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from urllib.parse import quote, urlencode

from .models import ConfigError, User, is_ip, validate_host, validate_port
from .xray_config import EGRESS_BLOCKED

HYSTERIA_VERSION = "app/v2.13.0"
# sha256 of the release binaries, from the GitHub release asset digests (published
# 2026-10-05); the amd64 one was re-verified by downloading the asset.
HYSTERIA_SHA256 = {
    "linux-amd64": "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691",
    "linux-arm64": "a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7",
}
SERVER_UNIT = "shahrah-hysteria2"

_BW_RE = re.compile(r"^[1-9][0-9]{0,4} (?:kbps|mbps|gbps)$")
_PIN_RE = re.compile(r"^[0-9a-f]{64}$")
_PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*(?P<body>[A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----"
)
MIN_SECRET = 16


@dataclass(frozen=True, slots=True)
class QuicTuning:
    """QUIC flow-control windows (bytes) and liveness timers."""

    init_stream_window: int
    max_stream_window: int
    init_conn_window: int
    max_conn_window: int
    max_idle_s: int = 30
    keepalive_s: int = 10  # client side; keeps mobile carrier NAT bindings open

    def __post_init__(self) -> None:
        if not 0 < self.init_stream_window <= self.max_stream_window:
            raise ConfigError("stream window: 0 < init <= max")
        if not 0 < self.init_conn_window <= self.max_conn_window:
            raise ConfigError("conn window: 0 < init <= max")
        if self.max_stream_window > self.max_conn_window:
            raise ConfigError("stream window must not exceed the connection window")
        if not 4 <= self.max_idle_s <= 120:
            raise ConfigError("max_idle_s must be 4..120")
        if not 2 <= self.keepalive_s < self.max_idle_s:
            raise ConfigError("keepalive_s must be >= 2 and below max_idle_s")


@dataclass(frozen=True, slots=True)
class Bandwidth:
    """Declared rates, Hysteria syntax (``"20 mbps"``). Empty strings = use BBR instead of
    Brutal (no declared rate), which is safer on links whose capacity is unknown."""

    up: str = ""
    down: str = ""

    def __post_init__(self) -> None:
        for value in (self.up, self.down):
            if value and not _BW_RE.match(value):
                raise ConfigError(f"bandwidth must look like '20 mbps': {value!r}")
        if bool(self.up) != bool(self.down):
            raise ConfigError("set both up and down bandwidth, or neither")


# Presets. "social": many short parallel flows (feed images, reels thumbnails, DMs). Modest
# windows cut queueing delay; 10/50 mbps per client is far above what a phone feed needs and
# stops Brutal from blasting a lossy link. "bulk" is Hysteria's own default sizing.
TUNING: dict[str, QuicTuning] = {
    "social": QuicTuning(2 << 20, 4 << 20, 5 << 20, 10 << 20, max_idle_s=30, keepalive_s=10),
    "bulk": QuicTuning(8 << 20, 8 << 20, 20 << 20, 20 << 20, max_idle_s=30, keepalive_s=10),
}
CLIENT_BANDWIDTH: dict[str, Bandwidth] = {
    "social": Bandwidth(up="10 mbps", down="50 mbps"),
    "bulk": Bandwidth(),
}


def generate_secret() -> str:
    return secrets.token_urlsafe(24)


def cert_pin(pem: str) -> str:
    """Lower-case hex SHA-256 of the first certificate's DER bytes (Hysteria ``pinSHA256``)."""
    match = _PEM_RE.search(pem)
    if match is None:
        raise ConfigError("no PEM certificate found")
    der = base64.b64decode("".join(match.group("body").split()))
    return hashlib.sha256(der).hexdigest()


def _check_secret(value: str, what: str) -> None:
    if len(value) < MIN_SECRET or any(ch in value for ch in '"\\\n:@/?#'):
        raise ConfigError(f"{what} must be >= {MIN_SECRET} chars without quotes, ':@/?#'")


def _check_hop(hop: tuple[int, int] | None, port: int) -> None:
    if hop is None:
        return
    low, high = hop
    validate_port(low, "hop range start")
    validate_port(high, "hop range end")
    if not 1024 < low < high or high - low < 100:
        raise ConfigError("hop range must be above 1024 and span at least 100 ports")
    if low <= port <= high:
        raise ConfigError("the listen port must lie outside the hop range")


@dataclass(frozen=True, slots=True)
class Hy2Settings:
    """Per-node Hysteria2 settings stored in the node state (contains the obfs secret)."""

    port: int = 8443
    obfs_password: str = ""
    sni: str = ""  # certificate name; empty = public host
    pin_sha256: str = ""  # self-signed: pin; empty = CA-signed certificate
    hop: tuple[int, int] | None = None  # UDP port-hopping range (DNAT to ``port``)
    tuning: str = "social"
    cert_path: str = "/etc/shahrah/hy2.crt"
    key_path: str = "/etc/shahrah/hy2.key"
    masquerade_url: str = "https://www.bing.com/"

    def __post_init__(self) -> None:
        validate_port(self.port, "hysteria2 port")
        _check_secret(self.obfs_password, "salamander obfs password")
        if self.sni:
            validate_host(self.sni, "hysteria2 sni")
            if is_ip(self.sni):
                raise ConfigError("hysteria2 sni must be a domain name")
        if self.pin_sha256 and not _PIN_RE.match(self.pin_sha256):
            raise ConfigError("pin_sha256 must be 64 lower-case hex chars (leaf cert DER)")
        if self.tuning not in TUNING:
            raise ConfigError(f"tuning must be one of {sorted(TUNING)}")
        for path in (self.cert_path, self.key_path):
            if not path.startswith("/") or any(ch.isspace() for ch in path):
                raise ConfigError("cert/key paths must be absolute without whitespace")
        if not self.masquerade_url.startswith("https://"):
            raise ConfigError("masquerade_url must be https://")
        _check_hop(self.hop, self.port)

    def to_dict(self) -> dict[str, object]:
        return {
            "port": self.port,
            "obfs_password": self.obfs_password,
            "sni": self.sni,
            "pin_sha256": self.pin_sha256,
            "hop": list(self.hop) if self.hop else None,
            "tuning": self.tuning,
            "cert_path": self.cert_path,
            "key_path": self.key_path,
            "masquerade_url": self.masquerade_url,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Hy2Settings:
        hop = data.get("hop")
        return cls(
            port=int(data.get("port", 8443)),  # type: ignore[arg-type]
            obfs_password=str(data["obfs_password"]),
            sni=str(data.get("sni", "")),
            pin_sha256=str(data.get("pin_sha256", "")),
            hop=(int(hop[0]), int(hop[1])) if hop else None,  # type: ignore[index]
            tuning=str(data.get("tuning", "social")),
            cert_path=str(data.get("cert_path", "/etc/shahrah/hy2.crt")),
            key_path=str(data.get("key_path", "/etc/shahrah/hy2.key")),
            masquerade_url=str(data.get("masquerade_url", "https://www.bing.com/")),
        )


def _q(value: object) -> str:
    return json.dumps(value)


def _quic_lines(t: QuicTuning, *, client: bool) -> list[str]:
    lines = [
        "quic:",
        f"  initStreamReceiveWindow: {t.init_stream_window}",
        f"  maxStreamReceiveWindow: {t.max_stream_window}",
        f"  initConnReceiveWindow: {t.init_conn_window}",
        f"  maxConnReceiveWindow: {t.max_conn_window}",
        f"  maxIdleTimeout: {_q(f'{t.max_idle_s}s')}",
    ]
    if client:
        lines.append(f"  keepAlivePeriod: {_q(f'{t.keepalive_s}s')}")
    return lines


def _obfs_lines(password: str) -> list[str]:
    return [
        "obfs:",
        '  type: "salamander"',
        "  salamander:",
        f"    password: {_q(password)}",
    ]


def render_server(settings: Hy2Settings, users: Sequence[User], *, listen_host: str = "") -> str:
    """Server YAML. Auth is per user (``label:uuid``), so revoking a user in Shahrah revokes
    their Hysteria access on the next ``apply``."""
    if not users:
        raise ConfigError("hysteria2 needs at least one user")
    lines = [
        "# rendered by shahrah; secret - keep mode 0600",
        f"listen: {_q(f'{listen_host}:{settings.port}')}",
        "tls:",
        f"  cert: {_q(settings.cert_path)}",
        f"  key: {_q(settings.key_path)}",
        *_obfs_lines(settings.obfs_password),
        *_quic_lines(TUNING[settings.tuning], client=False),
        # Share-link clients often omit bandwidth; without a server cap Brutal saturates a
        # lossy MTU-1400 path and large fetches stall. Cap to the social preset and ignore
        # a missing client declaration.
        "ignoreClientBandwidth: true",
        "speedTest: false",
        "bandwidth:",
        f"  up: {_q(CLIENT_BANDWIDTH[settings.tuning].up or '10 mbps')}",
        f"  down: {_q(CLIENT_BANDWIDTH[settings.tuning].down or '50 mbps')}",
        'udpIdleTimeout: "60s"',
        "auth:",
        '  type: "userpass"',
        "  userpass:",
        *(f"    {_q(u.label)}: {_q(u.uuid)}" for u in users),
        "masquerade:",
        '  type: "proxy"',
        "  proxy:",
        f"    url: {_q(settings.masquerade_url)}",
        "    rewriteHost: true",
        # Same egress policy as the Xray exit: no SSRF into the exit's LAN or loopback
        # (stats API, WaterWall/paqet listeners), and the reserved ranges Xray's freedom refuses.
        "acl:",
        "  inline:",
        *(f"    - {_q(f'reject({net})')}" for net in EGRESS_BLOCKED),
    ]
    return "\n".join(lines) + "\n"


def _server_addr(host: str, settings: Hy2Settings) -> str:
    shown = f"[{host}]" if is_ip(host) and ":" in host else host
    if settings.hop:
        return f"{shown}:{settings.hop[0]}-{settings.hop[1]}"
    return f"{shown}:{settings.port}"


def render_client(
    settings: Hy2Settings,
    host: str,
    user: User,
    *,
    socks_listen: str = "127.0.0.1:1080",
    server_port: int | None = None,
    insecure: bool = False,
) -> str:
    """Client YAML exposing a loopback SOCKS5 port (used by the prober and by relays).

    ``server_port`` overrides the address (loopback smoke tests skip the hop range).
    """
    validate_host(host, "hysteria2 server host")
    hostpart, _, port = socks_listen.rpartition(":")
    if hostpart not in {"127.0.0.1", "localhost"} or not port.isdigit():
        raise ConfigError("socks_listen must be loopback host:port (never expose SOCKS)")
    addr = f"{host}:{server_port}" if server_port is not None else _server_addr(host, settings)
    tls = ["tls:", f"  sni: {_q(settings.sni or host)}"]
    if settings.pin_sha256:
        # Hysteria only consults the pin after skipping CA verification; the pin (leaf DER
        # hash) is then the whole trust anchor, which is stricter than a CA for one server.
        tls.append(f"  pinSHA256: {_q(settings.pin_sha256)}")
    if insecure or settings.pin_sha256:
        tls.append("  insecure: true")
    bw = CLIENT_BANDWIDTH[settings.tuning]
    lines = [
        "# rendered by shahrah; secret - keep mode 0600",
        f"server: {_q(addr)}",
        f"auth: {_q(f'{user.label}:{user.uuid}')}",
        *tls,
        *_obfs_lines(settings.obfs_password),
        *_quic_lines(TUNING[settings.tuning], client=True),
    ]
    if bw.up:
        lines += ["bandwidth:", f"  up: {_q(bw.up)}", f"  down: {_q(bw.down)}"]
    if settings.hop and server_port is None:
        lines += ["transport:", '  type: "udp"', "  udp:", '    hopInterval: "30s"']
    # lazy: connect on first use, so a filtered path never crash-loops the unit.
    lines += ["fastOpen: true", "lazy: true", "socks5:", f"  listen: {_q(socks_listen)}"]
    return "\n".join(lines) + "\n"


def share_link(settings: Hy2Settings, host: str, user: User, name: str) -> str:
    """``hysteria2://`` URI understood by Hiddify, v2rayNG, NekoBox, Streisand, ..."""
    query: list[tuple[str, str]] = [
        ("sni", settings.sni or host),
        ("obfs", "salamander"),
        ("obfs-password", settings.obfs_password),
    ]
    if settings.pin_sha256:
        query += [("insecure", "1"), ("pinSHA256", settings.pin_sha256)]
    auth = f"{quote(user.label, safe='')}:{user.uuid}"
    params = urlencode(query, quote_via=quote)
    return f"hysteria2://{auth}@{_server_addr(host, settings)}/?{params}#{quote(name, safe='')}"


def hop_rules(settings: Hy2Settings, interface: str = "eth0") -> list[list[str]]:
    """iptables DNAT for UDP port hopping (per-port UDP throttling is common in Iran)."""
    if settings.hop is None:
        return []
    if not re.match(r"^[A-Za-z0-9_.:-]{1,32}$", interface):
        raise ConfigError(f"invalid interface: {interface!r}")
    low, high = settings.hop
    return [
        [
            "iptables",
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-i",
            interface,
            "-p",
            "udp",
            "--dport",
            f"{low}:{high}",
            "-j",
            "REDIRECT",
            "--to-ports",
            str(settings.port),
        ]
    ]


def systemd_unit(role: str, config_path: str, binary: str = "/usr/local/bin/hysteria") -> str:
    if role not in {"server", "client"}:
        raise ConfigError("role must be server or client")
    return (
        "[Unit]\n"
        f"Description=shahrah hysteria2 {role} (QUIC/UDP social path)\n"
        "After=network-online.target\nWants=network-online.target\n\n"
        "[Service]\n"
        f"ExecStart={binary} {role} -c {config_path} --disable-update-check\n"
        "Restart=always\nRestartSec=3\n"
        "User=shahrah\nGroup=shahrah\n"
        "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
        "NoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nLimitNOFILE=1048576\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class Hy2ProbeSession:
    """Run one Hysteria client exposing the path as a loopback SOCKS port for the prober."""

    def __init__(
        self,
        binary: str,
        settings: Hy2Settings,
        host: str,
        user: User,
        *,
        server_port: int | None = None,
        insecure: bool = False,
        startup_timeout: float = 10.0,
    ) -> None:
        self._binary = binary
        self._settings = settings
        self._host = host
        self._user = user
        self._server_port = server_port
        self._insecure = insecure
        self._startup_timeout = startup_timeout
        self.socks_port = 0
        self._proc: subprocess.Popen[bytes] | None = None
        self._tmp: tempfile.TemporaryDirectory[str] | None = None

    def __enter__(self) -> Hy2ProbeSession:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()

    def start(self) -> None:
        from .prober import ProbeError

        self.socks_port = _free_port()
        self._tmp = tempfile.TemporaryDirectory(prefix="shahrah-hy2-")
        cfg = Path(self._tmp.name) / "client.yaml"
        cfg.write_text(
            render_client(
                self._settings,
                self._host,
                self._user,
                socks_listen=f"127.0.0.1:{self.socks_port}",
                server_port=self._server_port,
                insecure=self._insecure,
            ),
            encoding="utf-8",
        )
        log_path = Path(self._tmp.name) / "client.log"
        with log_path.open("wb") as log:
            self._proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                [self._binary, "client", "-c", str(cfg), "--disable-update-check"],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        deadline = time.monotonic() + self._startup_timeout
        while True:
            if self._proc.poll() is not None:
                tail = log_path.read_text(errors="replace")[-600:]
                self.stop()
                raise ProbeError(f"hysteria exited during start-up: {tail.strip()}")
            try:
                socket.create_connection(("127.0.0.1", self.socks_port), timeout=0.3).close()
                return
            except OSError:
                if time.monotonic() > deadline:
                    self.stop()
                    raise ProbeError("hysteria did not open its SOCKS port in time") from None
                time.sleep(0.1)

    def stop(self) -> None:
        proc, self._proc = self._proc, None
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp = None
