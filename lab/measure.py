"""Run inside the `client` namespace (root): profile x path matrix, social workload, and the
brain/oracle failover scenario. Writes lab/results.json and lab/RESULTS.md."""

from __future__ import annotations

import json
import socket
import ssl
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from shahrah.brain import Brain, BrainConfig, Sidecar  # noqa: E402
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
    "open", "sni-dpi", "udp-block", "udp-throttle", "allowlist-ip",
    "icmp-only", "dns-poison", "lossy-mobile", "shutdown",
]
PATHS = ["reality-vision", "reality-xhttp", "reality-domain", "relay-ww", "hysteria2", "paqet"]
COVER_IP, COVER_SNI = "23.5.100.2", "cover.lab"
HTTP_TARGET = ProbeTarget(host=COVER_IP, port=80, path="/", tls=False,
                          expect_status=frozenset({200}))
SMALL_N, CONC, TIMEOUT = 20, 5, 6.0


def censor(profile: str) -> None:
    subprocess.run(["bash", str(HERE / "censor.sh"), profile], check=True,
                   stdout=subprocess.DEVNULL)
    time.sleep(1.0)


def https_get(port: int, path: str, timeout: float) -> tuple[float, float, int]:
    """(ttfb_ms, total_ms, body_bytes) for GET https://cover.lab<path> through SOCKS."""
    started = time.monotonic()
    sock = socks5_connect(port, COVER_IP, 443, timeout)
    ctx = ssl.create_default_context(cafile=str(RUN / "ca.crt"))
    with ctx.wrap_socket(sock, server_hostname=COVER_SNI) as tls:
        tls.settimeout(timeout)
        tls.sendall(f"GET {path} HTTP/1.1\r\nHost: {COVER_SNI}\r\nConnection: close\r\n\r\n".encode())
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
    eps = {e.port: e for e in state.endpoints()}
    vision, xhttp = eps[443], eps[80]
    return state, [
        replace(vision, name="reality-vision", priority=0),
        replace(xhttp, name="reality-xhttp", priority=1),
        replace(vision, name="reality-domain", host="exit.lab", priority=4),
        replace(vision, name="relay-ww", host="10.0.2.2", priority=3, lockdown_capable=True),
    ]


def matrix(xray: XrayProbeSession, hy2: Hy2ProbeSession) -> dict:
    ports = {e: xray.socks_port(e) for e in PATHS[:4]}
    ports["hysteria2"] = hy2.socks_port
    ports["paqet"] = 1080
    out: dict[str, dict] = {}
    for profile in PROFILES:
        censor(profile)
        out[profile] = {}
        for path in PATHS:
            out[profile][path] = workload(ports[path])
            print(profile, path, out[profile][path], flush=True)
    censor("open")
    return out


def brain_scenario(xray: XrayProbeSession, hy2: Hy2ProbeSession, eps: list) -> dict:
    by_name = {e.name: e for e in eps if e.name != "reality-domain"}
    state, _ = endpoints()
    cfg = BrainConfig(
        endpoints=tuple(by_name.values()),
        probe_user=state.users[0],
        remarks={},
        oracle=OracleConfig(fail_streak=2, recover_streak=2, min_dwell_s=0,
                            outage_after_cycles=2),
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
        ("shutdown", "outage", None),
        ("open", "normal", "reality-vision"),
    ]
    phases = []
    for profile, want_mode, want_active in plan:
        censor(profile)
        trace = []
        for _ in range(5):
            clock[0] += 30
            d = brain.cycle()
            if d is not None:
                trace.append({"mode": str(d.state.mode), "active": d.state.active,
                              "ranking": list(d.ranking)})
        last = trace[-1] if trace else {}
        active_ok = want_active is None or last.get("active") == want_active
        phases.append({
            "profile": profile, "expected_mode": want_mode, "expected_active": want_active,
            "observed": last, "trace": trace,
            "pass": last.get("mode") == want_mode and active_ok,
        })
        print("brain", profile, last, flush=True)
    censor("open")
    return {"phases": phases, "pass": all(p["pass"] for p in phases)}


def cell(r: dict) -> str:
    if not r.get("ok"):
        return "❌"
    media = f", 2MB {r['media_s']}s" if r.get("media_ok") else ", 2MB ❌"
    return (f"✅ {int(r['success'] * 100)}% ttfb {r['ttfb_p50_ms']} "
            f"p50 {r['p50_ms']} p95 {r['p95_ms']}{media}")


def write_md(data: dict) -> None:
    lines = [
        "# Lab results",
        "",
        f"Generated {data['generated']} by `lab/run.sh` (WSL2 netns, see README for limits).",
        f"Workload per cell: {SMALL_N} small HTTPS GETs (2 KB, {CONC} concurrent) + one 2 MB "
        "fetch through the path to the cover server. Times in ms.",
        "",
        "| profile | " + " | ".join(PATHS) + " |",
        "|---|" + "---|" * len(PATHS),
    ]
    for profile, row in data["matrix"].items():
        lines.append(f"| {profile} | " + " | ".join(cell(row[p]) for p in PATHS) + " |")
    lines += ["", "## Brain / oracle failover", "",
              "| censor profile | expected mode / active | observed | pass |", "|---|---|---|---|"]
    for ph in data["brain"]["phases"]:
        o = ph["observed"]
        lines.append(f"| {ph['profile']} | {ph['expected_mode']} / {ph['expected_active']} | "
                     f"{o.get('mode')} / {o.get('active')} | {'✅' if ph['pass'] else '❌'} |")
    (HERE / "RESULTS.md").write_text("\n".join(lines) + "\n")


def main() -> int:
    state, eps = endpoints()
    user = state.users[0]
    assert state.hysteria2 is not None
    with (
        XrayProbeSession(str(BIN / "xray"), eps, user, target=HTTP_TARGET) as xray,
        Hy2ProbeSession(str(BIN / "hysteria"), state.hysteria2, "10.0.4.2", user) as hy2,
    ):
        time.sleep(2)
        only = sys.argv[1:] or ["matrix", "brain"]
        data = {"generated": time.strftime("%Y-%m-%d %H:%M %Z"), "matrix": {}, "brain": {}}
        if "matrix" in only:
            data["matrix"] = matrix(xray, hy2)
        if "brain" in only:
            data["brain"] = brain_scenario(xray, hy2, eps)
    (HERE / "results.json").write_text(json.dumps(data, indent=2) + "\n")
    if data["matrix"] and data["brain"]:
        write_md(data)
    return 0 if not data["brain"] or data["brain"]["pass"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ProbeError as exc:
        print(f"probe machinery failed: {exc}", file=sys.stderr)
        sys.exit(3)
