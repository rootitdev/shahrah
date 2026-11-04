"""On-node readiness checks distilled from the manual ops scripts (docs/DIAG_LESSONS.md).

Every check is a pure function over text/data that the CLI gathers with ordinary system
tools (``ss``, ``nft``, ``sysctl``...), so each lesson is unit-tested without a server. The
CLI runs whatever tools exist and reports ``skip`` for the rest; nothing here changes the
system.
"""

from __future__ import annotations

import re
import shutil
import socket
import ssl
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from .hysteria2 import cert_pin
from .models import ConfigError


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    status: str  # ok | warn | fail | skip
    detail: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


# --- L1: REALITY target must answer TLS 1.3 *from this server* -----------------------------

TlsProbe = Callable[[str, int, float], str]  # returns negotiated version or raises OSError


def _tls_version(host: str, port: int, timeout: float) -> str:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    with (
        socket.create_connection((host, port), timeout=timeout) as raw,
        ctx.wrap_socket(raw, server_hostname=host) as tls,
    ):
        return tls.version() or ""


def reality_target(host: str, port: int = 443, probe: TlsProbe = _tls_version) -> Check:
    """A target that is filtered or slow from the server's own network makes every REALITY
    handshake fail or stall (repeated in the ops logs for Iran-hosted nodes)."""
    try:
        version = probe(host, port, 5.0)
    except (OSError, ssl.SSLError) as exc:
        return Check("reality-target", "fail", f"{host}:{port} unreachable/TLS<1.3: {exc}"[:160])
    if version != "TLSv1.3":
        return Check("reality-target", "fail", f"{host} negotiated {version or '?'}")
    return Check("reality-target", "ok", f"{host} TLS 1.3")


# --- L2: certificate pins are leaf-DER hashes, not SPKI ------------------------------------


def pin_matches(pem: str, pin: str) -> Check:
    """Xray ``pinnedPeerCertSha256`` and Hysteria ``pinSHA256`` hash the leaf certificate DER.
    An SPKI (public key) hash looks identical in shape and silently never matches."""
    clean = pin.replace(":", "").lower()
    try:
        leaf = cert_pin(pem)
    except ConfigError as exc:
        return Check("cert-pin", "fail", str(exc))
    if clean == leaf:
        return Check("cert-pin", "ok", "pin = sha256(leaf DER)")
    return Check(
        "cert-pin",
        "fail",
        f"pin does not match the leaf certificate (SPKI hash or stale cert?); expected {leaf}",
    )


# --- L3: no stray listener on the public ports ---------------------------------------------

_SS_PROC = re.compile(r'users:\(\("(?P<proc>[^"]+)"')


def port_owners(ss_output: str, ports: Sequence[int], allowed: Sequence[str]) -> Check:
    """``ss -ltnupH`` output: every public port must belong to an expected process. A leftover
    nginx/xray/panel core on 443 was the most common cause of "works, then doesn't"."""
    problems: list[str] = []
    for line in ss_output.splitlines():
        cols = line.split()
        local = next((c for c in cols if re.search(r":\d+$", c)), "")
        if not local:
            continue
        port = int(local.rsplit(":", 1)[1])
        if port not in ports:
            continue
        match = _SS_PROC.search(line)
        proc = match.group("proc") if match else "?"
        if proc not in allowed:
            problems.append(f"{port}:{proc}")
    if problems:
        return Check("port-owners", "fail", "unexpected listeners " + ", ".join(problems))
    return Check("port-owners", "ok", f"ports {list(ports)} owned by {sorted(set(allowed))}")


# --- L4: the firewall that is actually enforcing -------------------------------------------


def firewall_backend(nft_tables: str, ufw_active: bool) -> Check:
    """Rules added with ufw are useless when a separate nftables table (e.g. ``inet vpn``)
    drops first; ports looked "open" in ufw and were closed on the wire."""
    tables = [ln.strip() for ln in nft_tables.splitlines() if ln.strip().startswith("table ")]
    foreign = [t for t in tables if not re.search(r"ufw|filter$|nat$|mangle$|raw$", t)]
    if foreign and ufw_active:
        return Check(
            "firewall",
            "warn",
            f"ufw is active but nftables also has {foreign}; open ports in that table too",
        )
    if not ufw_active and not tables:
        return Check("firewall", "warn", "no firewall rules found")
    return Check("firewall", "ok", "ufw" if ufw_active else f"nftables {tables}")


# --- L5: never an open resolver; DNS listeners on loopback only ----------------------------


def dns_exposure(ss_output: str, allowed: Sequence[str] = ("xray",)) -> Check:
    """Port 53 on a public address must be the Xray crisis listener, never a resolver."""
    bad: list[str] = []
    for line in ss_output.splitlines():
        cols = line.split()
        local = next((c for c in cols if c.endswith(":53")), "")
        if not local:
            continue
        addr = local.rsplit(":", 1)[0].strip("[]")
        if addr.startswith("127.") or addr in {"::1", "%lo"} or addr.endswith("%lo"):
            continue
        match = _SS_PROC.search(line)
        proc = match.group("proc") if match else "?"
        if proc not in allowed:
            bad.append(f"{addr}:{proc}")
    if bad:
        return Check("dns-exposure", "fail", "public port 53 served by " + ", ".join(bad))
    return Check("dns-exposure", "ok", "no public resolver")


# --- L6: IPv6 that resolves but does not route ---------------------------------------------


def ipv6_sanity(name: str, aaaa: Sequence[str], has_ipv6_route: bool) -> Check:
    """CDN names with AAAA on a box without working IPv6 made clients/probes hang until the
    v6 attempt timed out; force IPv4 (``domainStrategy: UseIPv4``) on such nodes."""
    if aaaa and not has_ipv6_route:
        return Check("ipv6", "warn", f"{name} has AAAA but this host has no IPv6 route")
    return Check("ipv6", "ok", "")


# --- L7: churn sysctls ---------------------------------------------------------------------

RECOMMENDED_SYSCTL: Mapping[str, str] = {
    "net.ipv4.tcp_congestion_control": "bbr",
    "net.core.somaxconn": "65535",
    "net.ipv4.tcp_fin_timeout": "15",
    "net.ipv4.tcp_tw_reuse": "1",
    "net.ipv4.tcp_slow_start_after_idle": "0",
    "net.ipv4.tcp_mtu_probing": "1",
}


def sysctl_values(current: Mapping[str, str]) -> Check:
    off = {
        k: current.get(k, "?")
        for k, v in RECOMMENDED_SYSCTL.items()
        if current.get(k, "").split() != v.split()
    }
    if off:
        return Check("sysctl", "warn", f"differs from recommended: {off}")
    return Check("sysctl", "ok", "")


# --- runner --------------------------------------------------------------------------------


def _cmd(argv: Sequence[str]) -> str | None:
    if shutil.which(argv[0]) is None:
        return None
    try:
        res = subprocess.run(list(argv), capture_output=True, text=True, timeout=10, check=False)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired):
        return None
    return res.stdout


def run_all(
    *,
    reality_host: str | None,
    public_ports: Sequence[int],
    cert_pem: str | None = None,
    pin: str | None = None,
    allowed_procs: Sequence[str] = ("xray", "hysteria", "waterwall", "Waterwall", "paqet"),
    cmd: Callable[[Sequence[str]], str | None] = _cmd,
    tls_probe: TlsProbe = _tls_version,
) -> list[Check]:
    checks: list[Check] = []
    if reality_host:
        checks.append(reality_target(reality_host, probe=tls_probe))
    if cert_pem is not None and pin:
        checks.append(pin_matches(cert_pem, pin))
    ss = cmd(["ss", "-ltnupH"])
    if ss is None:
        checks.append(Check("port-owners", "skip", "ss not available"))
    else:
        checks.append(port_owners(ss, public_ports, allowed_procs))
        checks.append(dns_exposure(ss))
    nft = cmd(["nft", "list", "tables"])
    ufw = cmd(["ufw", "status"])
    if nft is None and ufw is None:
        checks.append(Check("firewall", "skip", "nft/ufw not available (need root)"))
    else:
        checks.append(firewall_backend(nft or "", bool(ufw and "Status: active" in ufw)))
    values: dict[str, str] = {}
    for key in RECOMMENDED_SYSCTL:
        got = cmd(["sysctl", "-n", key])
        if got is not None:
            values[key] = got.strip()
    checks.append(sysctl_values(values) if values else Check("sysctl", "skip", "no sysctl"))
    return checks
