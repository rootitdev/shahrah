"""Run inside the `client` namespace (root): profile x path matrix, social workload, and the
brain/oracle failover scenario. Writes lab/results.json and lab/RESULTS.md."""

from __future__ import annotations

import json
import os
import re
import socket
import ssl
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from shahrah.brain import Brain, BrainConfig, Sidecar  # noqa: E402
from shahrah import hysteria2 as hy2mod  # noqa: E402
from shahrah import prober as prober_mod  # noqa: E402
from shahrah.hysteria2 import Hy2ProbeSession  # noqa: E402
from shahrah.oracle import OracleConfig  # noqa: E402
from shahrah.prober import (  # noqa: E402
    ProbeError,
    ProbeTarget,
    XrayProbeSession,
    probe_socks,
    socks5_connect,
)
from shahrah.state import load_state  # noqa: E402

RUN = Path("/run/shahrah-lab")
BIN = Path("/root/shahrah-lab-bin")
PROFILES = [
    "open",
    "sni-dpi",
    "udp-block",
    "udp-throttle",
    "allowlist-ip",
    "icmp-only",
    "dns-poison",
    "lossy-mobile",
    "shutdown",
]
PATHS = [
    "reality-vision",
    "reality-xhttp",
    "reality-domain",
    "relay-ww",
    "cdn-xhttp",
    "hysteria2",
    "hysteria2-plain",
    "paqet",
]
XRAY_PATHS = PATHS[:5]
# (row name, client-leg profile, international-gateway profile)
ROWS = [(p, p, "open") for p in PROFILES] + [
    ("sni-dpi-strict", "sni-dpi-strict", "open"),
    ("intl:sni-dpi", "open", "sni-dpi"),
    ("intl:udp-block", "open", "udp-block"),
    ("intl:allowlist-ip", "open", "allowlist-ip"),
    ("intl:lossy-mobile", "open", "lossy-mobile"),
]
COVER_IP, COVER_SNI = "198.18.5.2", "cover.lab"
HTTP_TARGET = ProbeTarget(
    host=COVER_IP, port=80, path="/", tls=False, expect_status=frozenset({200})
)
SMALL_N, CONC, TIMEOUT = 20, 5, 6.0


def censor(client: str, intl: str = "open") -> None:
    """Both censor legs; "intl:<p>" as a client profile means open client leg + <p> abroad."""
    if client.startswith("intl:"):
        client, intl = "open", client[5:]
    for leg, prof in (("client", client), ("intl", intl)):
        subprocess.run(
            ["bash", str(HERE / "censor.sh"), "--leg", leg, prof],
            check=True,
            stdout=subprocess.DEVNULL,
        )
    time.sleep(1.0)


def _trust_lab_ca(render):  # noqa: ANN001, ANN202
    """Xray ignores SSL_CERT_FILE; let TLS outbounds (the cdn.lab edge) verify the lab CA."""

    def wrapped(*a, **kw):  # noqa: ANN002, ANN003, ANN202
        cfg = render(*a, **kw)
        for ob in cfg.get("outbounds", []):
            tls = ob.get("streamSettings", {}).get("tlsSettings")
            if tls is not None:
                tls["certificates"] = [{"usage": "verify", "certificateFile": str(RUN / "ca.crt")}]
        return cfg

    return wrapped


prober_mod.render_probe_config = _trust_lab_ca(prober_mod.render_probe_config)


class PlainHy2(Hy2ProbeSession):
    """Client for the lab's second Hysteria2 server (8444, no salamander: readable QUIC)."""

    def start(self) -> None:
        orig = hy2mod.render_client

        def plain(*a, **kw):  # noqa: ANN002, ANN003, ANN202
            return re.sub(r"(?m)^obfs:\n(?:  .*\n)+", "", orig(*a, **kw))

        hy2mod.render_client = plain
        try:
            super().start()
        finally:
            hy2mod.render_client = orig


def https_get(port: int, path: str, timeout: float) -> tuple[float, float, int]:
    """(ttfb_ms, total_ms, body_bytes) for GET https://cover.lab<path> through SOCKS."""
    started = time.monotonic()
    sock = socks5_connect(port, COVER_IP, 443, timeout)
    ctx = ssl.create_default_context(cafile=str(RUN / "ca.crt"))
    with ctx.wrap_socket(sock, server_hostname=COVER_SNI) as tls:
        tls.settimeout(timeout)
        tls.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {COVER_SNI}\r\nConnection: close\r\n\r\n".encode()
        )
        first = tls.recv(65536)
        if not first:
            raise ConnectionError("empty response")
        ttfb = (time.monotonic() - started) * 1000
        head, _, body = first.partition(b"\r\n\r\n")
        if b" 200 " not in head.split(b"\r\n")[0]:
            raise ConnectionError(head[:40])
        size = len(body)
        # Stop at Content-Length like a browser would; waiting for EOF would measure the
        # tunnel's half-close linger (Xray uplinkOnly/downlinkOnly) instead of the page.
        want = None
        for line in head.split(b"\r\n")[1:]:
            k, _, v = line.partition(b":")
            if k.strip().lower() == b"content-length":
                want = int(v.strip())
        while want is None or size < want:
            chunk = tls.recv(65536)
            if not chunk:
                break
            size += len(chunk)
    return ttfb, (time.monotonic() - started) * 1000, size


def pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    return round(values[min(len(values) - 1, int(len(values) * q))], 1)


def workload(port: int | None) -> dict:
    if port is None:
        return {"ok": False, "success": 0.0, "detail": "client not running"}
    probe = [_try(port, "/small") for _ in range(3)]
    if not any(r for r in probe):
        return {"ok": False, "success": 0.0, "detail": "first 3 requests failed"}
    with ThreadPoolExecutor(CONC) as pool:
        results = list(pool.map(lambda _: _try(port, "/small"), range(SMALL_N)))
    good = [r for r in results if r]
    media = _try(port, "/media", 40.0)
    return {
        "ok": bool(good),
        "success": round(len(good) / SMALL_N, 2),
        "ttfb_p50_ms": pct([r[0] for r in good], 0.5),
        "p50_ms": pct([r[1] for r in good], 0.5),
        "p95_ms": pct([r[1] for r in good], 0.95),
        "media_ok": bool(media and media[2] == 2 * 1024 * 1024),
        "media_s": round(media[1] / 1000, 2) if media else None,
    }


def _try(port: int, path: str, timeout: float = TIMEOUT) -> tuple[float, float, int] | None:
    try:
        return https_get(port, path, timeout)
    except (OSError, ssl.SSLError, ConnectionError, ValueError):
        return None


def endpoints():  # noqa: ANN201
    state = load_state(RUN / "exit-state.json")
    all_eps = state.endpoints()
    cdn = next(e for e in all_eps if e.name.endswith("-cdn-8080"))
    eps = {e.port: e for e in all_eps if e is not cdn}
    vision, xhttp = eps[443], eps[80]
    return state, [
        replace(vision, name="reality-vision", priority=0),
        replace(xhttp, name="reality-xhttp", priority=1),
        replace(vision, name="reality-domain", host="exit.lab", priority=4),
        replace(vision, name="relay-ww", host="10.0.2.2", priority=3, lockdown_capable=True),
        replace(cdn, name="cdn-xhttp", priority=6),
    ]


def matrix(state, eps: list) -> dict:  # noqa: ANN001
    """Every row gets brand-new client processes, started *after* the censor switched, so no
    pooled connection (XHTTP/H2, QUIC) from the previous profile can carry over."""
    user = state.users[0]
    out: dict[str, dict] = {}
    wanted = [r for r in os.environ.get("LAB_ROWS", "").split(",") if r]  # quick partial runs
    for row, client, intl in ROWS:
        if wanted and row not in wanted:
            continue
        censor(client, intl)
        out[row] = {}
        ports: dict[str, int | None] = {"paqet": 1080}
        with ExitStack() as stack:
            try:
                xray = stack.enter_context(
                    XrayProbeSession(str(BIN / "xray"), eps, user, target=HTTP_TARGET)
                )
                ports.update({e: xray.socks_port(e) for e in XRAY_PATHS})
            except ProbeError as exc:
                print(row, "xray client failed:", exc, flush=True)
            for name, cls, port in (
                ("hysteria2", Hy2ProbeSession, None),
                ("hysteria2-plain", PlainHy2, 8444),
            ):
                try:
                    s = stack.enter_context(
                        cls(
                            str(BIN / "hysteria"),
                            state.hysteria2,
                            "10.0.4.2",
                            user,
                            server_port=port,
                        )
                    )
                    ports[name] = s.socks_port
                except ProbeError as exc:
                    print(row, name, "client failed:", exc, flush=True)
            time.sleep(1.0)
            for path in PATHS:
                out[row][path] = workload(ports.get(path))
                print(row, path, out[row][path], flush=True)
    censor("open")
    return out


def brain_scenario(xray: XrayProbeSession, hy2: Hy2ProbeSession, eps: list) -> dict:
    by_name = {e.name: e for e in eps if e.name != "reality-domain"}
    state, _ = endpoints()
    cfg = BrainConfig(
        endpoints=tuple(by_name.values()),
        probe_user=state.users[0],
        remarks={},
        oracle=OracleConfig(fail_streak=2, recover_streak=2, min_dwell_s=0, outage_after_cycles=2),
        sidecars=(
            Sidecar("hysteria2", "hysteria2", hy2.socks_port, priority=2),
            Sidecar("paqet", "paqet", 1080, priority=5),
        ),
        interval_s=5,
    )

    def probe_round():  # noqa: ANN202
        names = list(by_name) + ["hysteria2", "paqet"]

        def one(n: str):  # noqa: ANN202
            if n == "hysteria2":
                return probe_socks(n, hy2.socks_port, HTTP_TARGET, timeout=4)
            if n == "paqet":
                return probe_socks(n, 1080, HTTP_TARGET, timeout=4)
            return xray.probe(n, 4.0, target=HTTP_TARGET)

        with ThreadPoolExecutor(len(names)) as pool:
            return list(pool.map(one, names))

    clock = [0.0]
    brain = Brain(cfg, probe_round, clock=lambda: clock[0])
    plan = [
        ("open", "normal", "reality-vision"),
        ("udp-block", "degraded", "reality-vision"),
        ("allowlist-ip", "restricted", "relay-ww"),
        ("intl:allowlist-ip", "restricted", "cdn-xhttp"),
        ("shutdown", "outage", None),
        ("open", "normal", "reality-vision"),
    ]
    phases = []
    for profile, want_mode, want_active in plan:
        censor(profile)
        trace = []
        # Up to 8 cycles; stop once the expectation holds (hysteresis needs a few cycles,
        # recovering from outage takes the longest). The cycle count is reported.
        last: dict = {}
        active_ok = False
        for _ in range(8):
            clock[0] += 30
            d = brain.cycle()
            if d is not None:
                last = {
                    "mode": str(d.state.mode),
                    "active": d.state.active,
                    "ranking": list(d.ranking),
                }
                trace.append(last)
            active_ok = want_active is None or last.get("active") == want_active
            if len(trace) >= 3 and last.get("mode") == want_mode and active_ok:
                break
        phases.append(
            {
                "profile": profile,
                "expected_mode": want_mode,
                "expected_active": want_active,
                "observed": last,
                "trace": trace,
                "cycles": len(trace),
                "pass": last.get("mode") == want_mode and active_ok,
            }
        )
        print("brain", profile, last, flush=True)
    censor("open")
    return {"phases": phases, "pass": all(p["pass"] for p in phases)}


def cell(r: dict) -> str:
    """Compact cell: p50/p95 of the small requests, 2 MB time; success shown when < 100 %."""
    if not r.get("ok"):
        return "❌"
    ok = "" if r["success"] >= 1 else f" ({int(r['success'] * 100)}%)"
    media = f"{r['media_s']}s" if r.get("media_ok") else "❌"
    return f"✅ {r['p50_ms']:.0f}/{r['p95_ms']:.0f} · {media}{ok}"


def write_md(data: dict) -> None:
    lines = [
        "# Lab results",
        "",
        f"Generated {data['generated']} by `lab/run.sh` (WSL2 netns, see README for limits).",
        f"Workload per cell: {SMALL_N} small HTTPS GETs (2 KB, {CONC} concurrent) + one 2 MB "
        "fetch through the path to the cover server. Cell: small p50/p95 ms · 2 MB seconds. "
        "Fresh client processes per row. `intl:` rows censor the international gateway "
        "(client leg open).",
        "",
        "| profile | " + " | ".join(PATHS) + " |",
        "|---|" + "---|" * len(PATHS),
    ]
    for profile, row in data["matrix"].items():
        lines.append(f"| {profile} | " + " | ".join(cell(row[p]) for p in PATHS) + " |")
    lines += [
        "",
        "## Brain / oracle failover",
        "",
        "| censor profile | expected mode / active | observed | cycles | pass |",
        "|---|---|---|---|---|",
    ]
    for ph in data["brain"]["phases"]:
        o = ph["observed"]
        lines.append(
            f"| {ph['profile']} | {ph['expected_mode']} / {ph['expected_active']} | "
            f"{o.get('mode')} / {o.get('active')} | {ph.get('cycles')} | "
            f"{'✅' if ph['pass'] else '❌'} |"
        )
    (HERE / "RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    state, eps = endpoints()
    user = state.users[0]
    assert state.hysteria2 is not None
    only = sys.argv[1:] or ["matrix", "brain"]
    data = {"generated": time.strftime("%Y-%m-%d %H:%M %Z"), "matrix": {}, "brain": {}}
    if "matrix" in only:
        data["matrix"] = matrix(state, eps)
    if "brain" in only:
        censor("open")
        with (
            XrayProbeSession(str(BIN / "xray"), eps, user, target=HTTP_TARGET) as xray,
            Hy2ProbeSession(str(BIN / "hysteria"), state.hysteria2, "10.0.4.2", user) as hy2,
        ):
            time.sleep(2)
            data["brain"] = brain_scenario(xray, hy2, eps)
    (HERE / "results.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if data["matrix"] and data["brain"]:
        write_md(data)
    return 0 if not data["brain"] or data["brain"]["pass"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ProbeError as exc:
        print(f"probe machinery failed: {exc}", file=sys.stderr)
        sys.exit(3)
