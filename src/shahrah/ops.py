"""Minimal operations console for the unified management plane.

This is the shell that will host SNI monitoring, (later) the Instagram traffic multiplier,
and links into PasarGuard. It deliberately:

* uses only the standard library (same constraint as the rest of Shahrah);
* binds to loopback by default;
* requires a shared token on every mutating / data request;
* never serves REALITY private keys or panel API keys;
* leaves PasarGuard as the system of record (linked, not forked).

Modules today: ``status`` (brain snapshot if a report file is present) and ``sni-scout``.
Placeholders advertise ``sni-watch`` and ``ig-mult`` so they cannot silently disappear from
the product surface.
"""

from __future__ import annotations

import json
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import sni_scout
from .models import ConfigError

Json = dict[str, Any]
ScoutFn = Callable[[list[str]], list[sni_scout.ScoutResult]]


@dataclass
class OpsConfig:
    token: str
    host: str = "127.0.0.1"
    port: int = 8787
    brain_status_path: str | None = None  # optional JSON written by an external status dump
    scout: ScoutFn = field(default=lambda hosts: sni_scout.scout(hosts))

    def __post_init__(self) -> None:
        if len(self.token) < 16:
            raise ConfigError("ops token must be at least 16 characters")
        public_all = "0.0.0.0"  # noqa: S104 - explicit operator opt-in only
        if self.host not in {"127.0.0.1", "::1", "localhost", public_all}:
            # Binding on a public address is allowed only when the operator opts in via
            # 0.0.0.0 and still needs the token; anything else is refused as a foot-gun.
            raise ConfigError("ops listen address must be loopback or 0.0.0.0")


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
 .soon{opacity:.55}
</style>
<h1>Shahrah ops</h1>
<p>Unified operations shell. PasarGuard stays the user/billing panel;
this console is for routing health, SNI choice, and (later) watch / Instagram tools.</p>
<div class="mod"><h2>Status</h2><pre id="status">loading…</pre></div>
<div class="mod"><h2>SNI scout</h2>
<p>Probe candidate REALITY targets from this vantage.</p>
<input id="hosts" size="60" value="www.samsung.com www.cloudflare.com www.microsoft.com">
<button id="scout">Run</button>
<pre id="scout-out"></pre></div>
<div class="mod soon"><h2>SNI watch</h2>
<p>Per-user / aggregate SNI observation — planned module (kept in product).</p></div>
<div class="mod soon"><h2>Instagram multiplier</h2>
<p>Category traffic accounting for billing — planned, without browsing logs.</p></div>
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
}
document.getElementById("scout").onclick = async () => {
  const hosts = document.getElementById("hosts").value.trim().split(/\\s+/);
  const r = await fetch("/api/sni-scout", {method:"POST", headers: hdr(),
    body: JSON.stringify({hosts})});
  document.getElementById("scout-out").textContent = await r.text();
};
refresh();
</script>
"""


def _unauthorized(handler: BaseHTTPRequestHandler) -> None:
    handler.send_response(401)
    handler.send_header("Content-Type", "application/json")
    handler.end_headers()
    handler.wfile.write(b'{"error":"unauthorized"}\n')


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
                payload: Json = {
                    "modules": {
                        "status": "ready",
                        "sni_scout": "ready",
                        "sni_watch": "planned",
                        "ig_mult": "planned",
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
            self._json(404, {"error": "not found"})

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
                if not hosts:
                    qs = parse_qs(urlparse(self.path).query)
                    hosts = qs.get("host", [])
                results = config.scout(hosts)
            except (ValueError, ConfigError, TypeError) as exc:
                return self._json(400, {"error": str(exc)})
            return self._json(
                200,
                {
                    "ranking": list(sni_scout.ranking(results)),
                    "results": [
                        {
                            "host": r.host,
                            "ok": r.ok,
                            "latency_ms": r.latency_ms,
                            "tls_version": r.tls_version,
                            "alpn": r.alpn,
                            "detail": r.detail,
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
