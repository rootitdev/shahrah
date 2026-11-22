"""Minimal operations console for the unified management plane.

This is the shell that hosts SNI monitoring, the Instagram traffic multiplier, usage, and
links into PasarGuard. It deliberately:

* uses only the standard library (same constraint as the rest of Shahrah);
* binds to loopback by default;
* requires a shared token on every mutating / data request;
* never serves REALITY private keys or panel API keys;
* leaves PasarGuard as the system of record (linked, not forked).

Modules: ``status``, ``sni-scout``, ``sni-watch`` (opt-in access log), ``usage``, ``ig-mult``.
"""

from __future__ import annotations

import json
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import accounting, ig_mult, sni_scout, sni_watch
from .models import ConfigError

Json = dict[str, Any]
ScoutFn = Callable[..., list[sni_scout.ScoutResult]]
UsageFn = Callable[[], dict[str, accounting.UserTraffic]]


def _default_scout(hosts: list[str], **kwargs: object) -> list[sni_scout.ScoutResult]:
    return sni_scout.scout(hosts, **kwargs)  # type: ignore[arg-type]


@dataclass
class OpsConfig:
    token: str
    host: str = "127.0.0.1"
    port: int = 8787
    brain_status_path: str | None = None  # optional JSON written by an external status dump
    access_log_path: str | None = None  # opt-in; powers /api/sni-watch and ig-mult shares
    watchlist_path: str | None = None
    retention_hours: float = 48.0
    stats_server: str | None = None  # e.g. 127.0.0.1:10085 for /api/usage
    xray_bin: str = "xray"
    ig_mult_path: str | None = None  # JSON file for Instagram multiplier settings
    scout: ScoutFn = field(default=_default_scout)
    usage: UsageFn | None = None
    ig: ig_mult.IgMultState | None = None

    def __post_init__(self) -> None:
        if len(self.token) < 16:
            raise ConfigError("ops token must be at least 16 characters")
        public_all = "0.0.0.0"  # noqa: S104 - explicit operator opt-in only
        if self.host not in {"127.0.0.1", "::1", "localhost", public_all}:
            # Binding on a public address is allowed only when the operator opts in via
            # 0.0.0.0 and still needs the token; anything else is refused as a foot-gun.
            raise ConfigError("ops listen address must be loopback or 0.0.0.0")
        if self.retention_hours <= 0:
            raise ConfigError("ops retention_hours must be positive")
        if self.ig is None and self.ig_mult_path:
            log = Path(self.access_log_path) if self.access_log_path else None
            self.ig = ig_mult.IgMultState(
                config_path=Path(self.ig_mult_path),
                access_log_path=log,
                retention_hours=self.retention_hours,
            )
            self.ig.reload()


def generate_token() -> str:
    return secrets.token_urlsafe(24)


_INDEX = """<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Shahrah ops</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;
 line-height:1.45}
 code,pre{background:#f4f4f5;padding:.1rem .3rem;border-radius:4px}
 pre{padding:.75rem;overflow:auto}
 .mod{border-top:1px solid #ddd;padding:1rem 0}
</style>
<h1>Shahrah ops</h1>
<p>Unified operations shell. PasarGuard stays the user/billing panel;
this console is for routing health, SNI choice, watch, usage, and Instagram billing weight.</p>
<div class="mod"><h2>Status</h2><pre id="status">loading…</pre></div>
<div class="mod"><h2>SNI scout</h2>
<p>Live REALITY target ranking from this vantage (run ops on the exit).
CDN edges use your own hostname — they are not in this list.</p>
<input id="hosts" size="60" placeholder="optional hosts; empty = built-in defaults"
 value="">
<button id="scout">Rank live</button>
<pre id="scout-out"></pre></div>
<div class="mod"><h2>Usage</h2>
<p>Per-user bytes from the loopback StatsService (independent nodes).</p>
<button id="usage">Refresh</button>
<pre id="usage-out">not configured</pre></div>
<div class="mod"><h2>SNI watch</h2>
<p>Opt-in destination aggregation from the Xray access log (off unless
<code>--access-log</code> was passed to <code>shahrah ops</code>).</p>
<button id="watch">Refresh</button>
<pre id="watch-out">not configured</pre></div>
<div class="mod"><h2>Instagram multiplier</h2>
<p>Category billing weight from opt-in access-log hit shares (no permanent browse archive).
Coefficient &lt; 1 discounts Instagram CDN traffic; 1.0 leaves quotas unchanged.</p>
<label>enabled <input id="ig-en" type="checkbox"></label>
<label>coefficient <input id="ig-coeff" type="number" step="0.05" min="0" max="10"
 value="1"></label>
<button id="ig-save">Save</button>
<button id="ig-est">Estimate billed</button>
<pre id="ig-out"></pre></div>
<div class="mod"><h2>PasarGuard</h2>
<p>User, sales and subscription management lives in the PasarGuard panel.
Shahrah steers its hosts via the brain; it does not fork the panel.</p></div>
<script>
const token = localStorage.getItem("shahrah_ops_token") || prompt("Ops token");
if (token) localStorage.setItem("shahrah_ops_token", token);
const hdr = () => ({"X-Ops-Token": token || "", "Content-Type":"application/json"});
async function refresh(){
  const r = await fetch("/api/status", {headers: hdr()});
  document.getElementById("status").textContent = await r.text();
  const ig = await fetch("/api/ig-mult", {headers: hdr()});
  const body = await ig.json();
  if (body.config) {
    document.getElementById("ig-en").checked = !!body.config.enabled;
    document.getElementById("ig-coeff").value = body.config.coefficient;
    document.getElementById("ig-out").textContent = JSON.stringify(body, null, 2);
  } else {
    document.getElementById("ig-out").textContent = await ig.text();
  }
}
document.getElementById("scout").onclick = async () => {
  const raw = document.getElementById("hosts").value.trim();
  const hosts = raw ? raw.split(/\\s+/) : [];
  const r = await fetch("/api/sni-scout", {method:"POST", headers: hdr(),
    body: JSON.stringify({hosts, defaults: hosts.length === 0})});
  document.getElementById("scout-out").textContent = await r.text();
};
document.getElementById("watch").onclick = async () => {
  const r = await fetch("/api/sni-watch", {headers: hdr()});
  document.getElementById("watch-out").textContent = await r.text();
};
document.getElementById("usage").onclick = async () => {
  const r = await fetch("/api/usage", {headers: hdr()});
  document.getElementById("usage-out").textContent = await r.text();
};
document.getElementById("ig-save").onclick = async () => {
  const r = await fetch("/api/ig-mult", {method:"PUT", headers: hdr(),
    body: JSON.stringify({
      enabled: document.getElementById("ig-en").checked,
      coefficient: Number(document.getElementById("ig-coeff").value)
    })});
  document.getElementById("ig-out").textContent = await r.text();
};
document.getElementById("ig-est").onclick = async () => {
  const r = await fetch("/api/ig-mult?estimate=1", {headers: hdr()});
  document.getElementById("ig-out").textContent = await r.text();
};
refresh();
</script>
"""


def _unauthorized(handler: BaseHTTPRequestHandler) -> None:
    handler.send_response(401)
    handler.send_header("Content-Type", "application/json")
    handler.end_headers()
    handler.wfile.write(b'{"error":"unauthorized"}\n')


def _load_usage(config: OpsConfig) -> dict[str, accounting.UserTraffic]:
    if config.usage is not None:
        return config.usage()
    if not config.stats_server:
        raise ConfigError("stats server not configured (needed for ig-mult estimate)")
    return accounting.query_stats(xray_bin=config.xray_bin, server=config.stats_server)


def make_handler(config: OpsConfig) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return  # keep stdout clean; operators use journald

        def _authorized(self) -> bool:
            return secrets.compare_digest(self.headers.get("X-Ops-Token", ""), config.token)

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/":
                body = _INDEX.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/api/status":
                if not self._authorized():
                    return _unauthorized(self)
                watch_state = "ready" if config.access_log_path else "cli-ready"
                usage_state = "ready" if (config.stats_server or config.usage) else "cli-ready"
                ig_state = "ready" if config.ig is not None else "cli-ready"
                payload: Json = {
                    "modules": {
                        "status": "ready",
                        "sni_scout": "ready",
                        "sni_watch": watch_state,
                        "usage": usage_state,
                        "ig_mult": ig_state,
                        "pasarguard": "external",
                    }
                }
                if config.brain_status_path:
                    try:
                        payload["brain"] = json.loads(
                            Pathish(config.brain_status_path).read_text(encoding="utf-8")
                        )
                    except (OSError, ValueError) as exc:
                        payload["brain_error"] = str(exc)
                return self._json(200, payload)
            if path == "/api/usage":
                if not self._authorized():
                    return _unauthorized(self)
                if not (config.stats_server or config.usage):
                    return self._json(
                        503,
                        {
                            "error": "stats server not configured",
                            "hint": "pass --stats-server to shahrah ops",
                        },
                    )
                try:
                    if config.usage is not None:
                        traffic = config.usage()
                    else:
                        server = config.stats_server or ""
                        traffic = accounting.query_stats(xray_bin=config.xray_bin, server=server)
                    return self._json(200, {label: row.as_dict() for label, row in traffic.items()})
                except ConfigError as exc:
                    return self._json(400, {"error": str(exc)})
            if path == "/api/sni-watch":
                if not self._authorized():
                    return _unauthorized(self)
                if not config.access_log_path:
                    return self._json(
                        503,
                        {
                            "error": "access log not configured",
                            "hint": "pass --access-log to shahrah ops",
                        },
                    )
                try:
                    store = sni_watch.WatchStore(retention_s=config.retention_hours * 3600)
                    store.ingest_file(Path(config.access_log_path))
                    watchlist = None
                    if config.watchlist_path:
                        watchlist = sni_watch.load_watchlist(Path(config.watchlist_path))
                    return self._json(200, store.summary(watchlist=watchlist))
                except ConfigError as exc:
                    return self._json(400, {"error": str(exc)})
            if path == "/api/ig-mult":
                if not self._authorized():
                    return _unauthorized(self)
                if config.ig is None:
                    return self._json(
                        503,
                        {
                            "error": "ig-mult not configured",
                            "hint": "pass --ig-mult-config to shahrah ops",
                        },
                    )
                qs = parse_qs(urlparse(self.path).query)
                want_estimate = qs.get("estimate", ["0"])[0] in {"1", "true", "yes"}
                try:
                    if want_estimate:
                        raw_traffic = _load_usage(config)
                        return self._json(200, config.ig.estimate(raw_traffic))
                    return self._json(200, {"config": config.ig.config.as_dict()})
                except ConfigError as exc:
                    return self._json(400, {"error": str(exc)})
            self._json(404, {"error": "not found"})

        def do_PUT(self) -> None:
            path = urlparse(self.path).path
            if path != "/api/ig-mult":
                return self._json(404, {"error": "not found"})
            if not self._authorized():
                return _unauthorized(self)
            if config.ig is None:
                return self._json(
                    503,
                    {
                        "error": "ig-mult not configured",
                        "hint": "pass --ig-mult-config to shahrah ops",
                    },
                )
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
                if not isinstance(body, dict):
                    raise ConfigError("body must be a JSON object")
                # Preserve existing suffixes unless the client sends a new list.
                current = config.ig.config.as_dict()
                merged = {**current, **body}
                updated = config.ig.update(ig_mult.parse_config_payload(merged))
            except (ValueError, ConfigError, TypeError) as exc:
                return self._json(400, {"error": str(exc)})
            return self._json(200, {"config": updated.as_dict()})

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            if path != "/api/sni-scout":
                return self._json(404, {"error": "not found"})
            if not self._authorized():
                return _unauthorized(self)
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
                hosts = list(body.get("hosts") or [])
                use_defaults = bool(body.get("defaults"))
                if not hosts:
                    qs = parse_qs(urlparse(self.path).query)
                    hosts = qs.get("host", [])
                    use_defaults = use_defaults or "defaults" in qs
                results = config.scout(hosts, use_defaults=use_defaults or not hosts)
            except (ValueError, ConfigError, TypeError) as exc:
                return self._json(400, {"error": str(exc)})
            return self._json(
                200,
                {
                    "ranking": list(sni_scout.ranking(results)),
                    "architecture": "reality",
                    "results": [
                        {
                            "host": r.host,
                            "ok": r.ok,
                            "latency_ms": r.latency_ms,
                            "tls_version": r.tls_version,
                            "alpn": r.alpn,
                            "detail": r.detail,
                            "architectures": list(r.architectures),
                        }
                        for r in results
                    ],
                },
            )

        def _json(self, status: int, payload: Json) -> None:
            data = (json.dumps(payload, indent=2) + "\n").encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


class Pathish:
    """Tiny Path stand-in so tests can inject a fake without importing pathlib in the handler."""

    def __init__(self, path: str) -> None:
        from pathlib import Path

        self._path = Path(path)

    def read_text(self, encoding: str = "utf-8") -> str:
        return self._path.read_text(encoding=encoding)


def serve(config: OpsConfig, *, forever: bool = True) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((config.host, config.port), make_handler(config))
    if forever:
        server.serve_forever()
    else:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
    return server
