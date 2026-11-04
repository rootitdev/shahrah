"""Rank candidate TLS sites for use as a REALITY ``target`` / SNI.

REALITY only works well against sites that speak TLS 1.3, present a stable certificate, and
answer quickly from the *exit* (Xray dials the target on every new connection). This module
probes candidates from the current vantage and returns a ranked list. It performs no DNS
publishing and never stores infrastructure secrets.

A candidate is rejected when:

* the TCP connect or TLS handshake fails / times out;
* the negotiated TLS version is below 1.3 (REALITY requires 1.3);
* the certificate does not cover the probed name;
* the host is on the known-risky Apple/iCloud suffix list (see ``RISKY_TARGET_SUFFIXES``).

Among the survivors, lower handshake latency ranks first.
"""

from __future__ import annotations

import socket
import ssl
import time
from collections.abc import Sequence
from dataclasses import dataclass

from .models import RISKY_TARGET_SUFFIXES, ConfigError, is_ip, validate_host

DEFAULT_TIMEOUT_S = 5.0

# Safe-ish public sites often usable as REALITY dest/SNI. Scout from the *exit*
# (foreign VPS), not from Iran. Never treat these as CDN edge hostnames.
DEFAULT_REALITY_CANDIDATES: tuple[str, ...] = (
    "www.cloudflare.com",
    "www.microsoft.com",
    "www.samsung.com",
    "dl.google.com",
    "www.logitech.com",
    "www.asus.com",
    "www.sony.com",
)


@dataclass(frozen=True, slots=True)
class ScoutResult:
    host: str
    ok: bool
    latency_ms: float | None
    tls_version: str | None
    alpn: str | None
    detail: str = ""
    architectures: tuple[str, ...] = ()

    def with_arch(self) -> ScoutResult:
        """Tag survivors as REALITY-capable; CDN edges use operator-owned names, not these."""
        arch: tuple[str, ...] = ("reality",) if self.ok else ()
        return ScoutResult(
            self.host,
            self.ok,
            self.latency_ms,
            self.tls_version,
            self.alpn,
            self.detail,
            arch,
        )


def _handshake(host: str, port: int, timeout_s: float) -> ScoutResult:
    started = time.perf_counter()
    context = ssl.create_default_context()
    # REALITY borrows a real handshake; we require a publicly trusted cert like a browser would.
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["h2", "http/1.1"])
    try:
        with (
            socket.create_connection((host, port), timeout=timeout_s) as raw,
            context.wrap_socket(raw, server_hostname=host) as tls,
        ):
            latency = (time.perf_counter() - started) * 1000
            version = tls.version() or ""
            if version not in {"TLSv1.3", "TLS 1.3"}:
                return ScoutResult(
                    host,
                    False,
                    latency,
                    version,
                    tls.selected_alpn_protocol(),
                    f"need TLS 1.3, got {version!r}",
                )
            cert = tls.getpeercert()
            if not cert:
                return ScoutResult(
                    host,
                    False,
                    latency,
                    version,
                    tls.selected_alpn_protocol(),
                    "empty certificate",
                )
            return ScoutResult(host, True, latency, version, tls.selected_alpn_protocol(), "ok")
    except ssl.SSLCertVerificationError as exc:
        return ScoutResult(host, False, None, None, None, f"cert: {exc}")
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        return ScoutResult(host, False, None, None, None, f"{type(exc).__name__}: {exc}")


def scout(
    hosts: Sequence[str] | None = None,
    *,
    port: int = 443,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    allow_risky: bool = False,
    use_defaults: bool = False,
) -> list[ScoutResult]:
    """Probe ``hosts`` and return every result (failures included), best-first among successes.

    When ``hosts`` is empty and ``use_defaults`` is true, probe ``DEFAULT_REALITY_CANDIDATES``
    (skipping risky suffixes unless ``allow_risky``). Run this on the exit node that will dial
    the REALITY target so latency reflects the production path.
    """
    incoming = list(hosts or [])
    if not incoming and use_defaults:
        incoming = [
            h
            for h in DEFAULT_REALITY_CANDIDATES
            if allow_risky or not h.endswith(RISKY_TARGET_SUFFIXES)
        ]
    if not incoming:
        raise ConfigError("at least one host is required (or pass use_defaults=True)")
    cleaned: list[str] = []
    for host in incoming:
        validate_host(host, "sni scout host")
        if is_ip(host):
            raise ConfigError(f"REALITY target must be a domain name, not an IP: {host!r}")
        if host.endswith(RISKY_TARGET_SUFFIXES) and not allow_risky:
            raise ConfigError(
                f"{host!r} is a known risky REALITY target; pass allow_risky=True to force it"
            )
        cleaned.append(host)

    results = [_handshake(host, port, timeout_s).with_arch() for host in cleaned]
    ok = sorted(
        (r for r in results if r.ok), key=lambda r: (r.latency_ms is None, r.latency_ms, r.host)
    )
    bad = [r for r in results if not r.ok]
    return [*ok, *bad]


def ranking(results: Sequence[ScoutResult]) -> tuple[str, ...]:
    """Domain names that passed, best first."""
    ok = [r for r in results if r.ok]
    ok.sort(key=lambda r: (r.latency_ms is None, r.latency_ms, r.host))
    return tuple(r.host for r in ok)
