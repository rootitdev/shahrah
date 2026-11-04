"""Serve base64 subscription bodies for ready-made clients.

Clients (v2rayNG, Hiddify, …) fetch a URL with no custom headers, so auth is a long random
path segment rather than a bearer token. Default bind is loopback; expose it through an SSH
tunnel or put a TLS reverse proxy in front.
"""

from __future__ import annotations

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .links import build_subscription
from .models import ConfigError
from .state import load_state


def generate_path_secret() -> str:
    return secrets.token_urlsafe(24)


def make_handler(state_path: Path, path_secret: str) -> type[BaseHTTPRequestHandler]:
    if len(path_secret) < 16:
        raise ConfigError("subscription path secret must be at least 16 characters")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            parts = [p for p in parsed.path.split("/") if p]
            if len(parts) == 2 and parts[0] == path_secret:
                return self._sub(parts[1])
            if parsed.path in {"/", "/health"}:
                body = b"ok\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def _sub(self, label: str) -> None:
            try:
                state = load_state(state_path)
                user = state.find_user(label)
                body = build_subscription(state.endpoints(), user).encode()
            except (ConfigError, OSError, ValueError) as exc:
                data = json.dumps({"error": str(exc)}).encode()
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def serve(
    state_path: Path,
    path_secret: str,
    *,
    host: str = "127.0.0.1",
    port: int = 8788,
    forever: bool = True,
) -> ThreadingHTTPServer:
    public_all = "0.0.0.0"  # noqa: S104
    if host not in {"127.0.0.1", "::1", "localhost", public_all}:
        raise ConfigError("subscription listen address must be loopback or 0.0.0.0")
    # Touch the state once so a missing file fails before we bind.
    load_state(state_path)
    server = ThreadingHTTPServer((host, port), make_handler(state_path, path_secret))
    if forever:
        server.serve_forever()
    else:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def subscription_url(host: str, port: int, path_secret: str, label: str) -> str:
    return f"http://{host}:{port}/{path_secret}/{label}"
