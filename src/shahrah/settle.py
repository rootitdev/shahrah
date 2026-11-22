"""Payment → PasarGuard credit bridge (Shahrah-owned stand-in for settle-web/pay).

The historical vpn-patch settle-web stack is not vendored here (AGPL / private). This
module is a minimal, testable webhook: a payment provider POSTs a signed JSON body and
Shahrah extends the matching PasarGuard user's expiry and/or data limit via the public
REST API. Swap the transport for YooKassa/Zarinpal/… later without touching the VPN core.

Security:

* shared HMAC secret (env), constant-time compare;
* loopback bind by default;
* never logs the API key or the HMAC secret.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .models import ConfigError
from .panel import PanelClient, PanelError

Json = dict[str, Any]
CreditFn = Callable[[str, int, int], None]  # username, add_seconds, add_bytes


@dataclass(frozen=True, slots=True)
class SettleEvent:
    username: str
    add_expire_s: int = 0
    add_bytes: int = 0
    payment_id: str = ""

    def __post_init__(self) -> None:
        if not self.username.strip():
            raise ConfigError("settle username must not be empty")
        if self.add_expire_s < 0 or self.add_bytes < 0:
            raise ConfigError("settle credit amounts must be non-negative")
        if self.add_expire_s == 0 and self.add_bytes == 0:
            raise ConfigError("settle event must credit expiry and/or bytes")


def parse_event(payload: Mapping[str, Any]) -> SettleEvent:
    """Accept Shahrah-native fields or a thin provider alias layer.

    Aliases (optional): ``days`` -> ``add_expire_s`` (86400 * days),
    ``traffic_gb`` -> ``add_bytes``.
    Payment providers map their webhook into this shape before POSTing here.
    """
    data = dict(payload)
    if "add_expire_s" not in data and data.get("days") is not None:
        data["add_expire_s"] = int(float(data["days"]) * 86400)
    if "add_bytes" not in data and data.get("traffic_gb") is not None:
        data["add_bytes"] = int(float(data["traffic_gb"]) * (1024**3))
    return SettleEvent(
        username=str(data.get("username", "")).strip(),
        add_expire_s=int(data.get("add_expire_s") or 0),
        add_bytes=int(data.get("add_bytes") or 0),
        payment_id=str(data.get("payment_id") or ""),
    )


def signed_request(
    secret: str,
    event: SettleEvent | Mapping[str, Any],
    *,
    base_url: str = "http://127.0.0.1:8790",
) -> dict[str, str]:
    """Build headers + body a payment provider (or curl) should POST to the settle hook."""
    if isinstance(event, SettleEvent):
        payload = {
            "username": event.username,
            "add_expire_s": event.add_expire_s,
            "add_bytes": event.add_bytes,
            "payment_id": event.payment_id,
        }
    else:
        payload = dict(event)
        # Normalize aliases so the body matches what parse_event accepts.
        parsed = parse_event(payload)
        payload = {
            "username": parsed.username,
            "add_expire_s": parsed.add_expire_s,
            "add_bytes": parsed.add_bytes,
            "payment_id": parsed.payment_id,
        }
    body = json.dumps(payload, separators=(",", ":")).encode()
    return {
        "url": f"{base_url.rstrip('/')}/hooks/payment",
        "body": body.decode(),
        "signature": sign_body(secret, body),
        "header": "X-Shahrah-Signature",
    }


def sign_body(secret: str, body: bytes) -> str:
    if len(secret) < 16:
        raise ConfigError("settle HMAC secret must be at least 16 characters")
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def verify_signature(secret: str, body: bytes, signature: str) -> bool:
    expected = sign_body(secret, body)
    return secrets.compare_digest(expected, (signature or "").strip().lower())


def _as_unix_expire(value: object) -> int:
    """PasarGuard may return ``expire`` as unix seconds or an ISO-8601 string."""
    if value is None or value == "" or value == 0:
        return 0
    if isinstance(value, bool):
        raise ConfigError("invalid expire value")
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    # e.g. 2026-10-25T19:13:09Z
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return int(datetime.fromisoformat(text).timestamp())
    except ValueError as exc:
        raise ConfigError(f"cannot parse expire {value!r}") from exc


def credit_user(client: PanelClient, event: SettleEvent) -> Json:
    """Read-modify-write the panel user: add seconds to ``expire`` and bytes to ``data_limit``.

    ``expire``/``data_limit`` of ``0`` mean unlimited in PasarGuard; we refuse to "add" onto
    unlimited so a buggy provider cannot silently change the product semantics.
    """
    user = client.get_user(event.username)
    expire = _as_unix_expire(user.get("expire"))
    limit = int(user.get("data_limit") or 0)
    if event.add_expire_s and expire == 0:
        raise ConfigError("refusing to extend an unlimited-expiry user")
    if event.add_bytes and limit == 0:
        raise ConfigError("refusing to extend an unlimited-traffic user")
    body = dict(user)
    if event.add_expire_s:
        # Write unix seconds; panels that prefer ISO still accept epoch in many builds.
        body["expire"] = expire + event.add_expire_s
    if event.add_bytes:
        body["data_limit"] = limit + event.add_bytes
    updated = client.put_user(event.username, body)
    new_expire = _as_unix_expire(updated.get("expire", body.get("expire", expire)))
    return {
        "username": event.username,
        "expire": new_expire,
        "data_limit": int(updated.get("data_limit", body.get("data_limit", limit))),
        "payment_id": event.payment_id,
    }


def make_handler(secret: str, credit: CreditFn) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_POST(self) -> None:
            if urlparse(self.path).path != "/hooks/payment":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            sig = self.headers.get("X-Shahrah-Signature", "")
            if not verify_signature(secret, raw, sig):
                self._json(401, {"error": "bad signature"})
                return
            try:
                event = parse_event(json.loads(raw.decode("utf-8") or "{}"))
                credit(event.username, event.add_expire_s, event.add_bytes)
            except (ConfigError, PanelError, ValueError, TypeError, json.JSONDecodeError) as exc:
                self._json(400, {"error": str(exc)})
                return
            self._json(
                200, {"ok": True, "username": event.username, "payment_id": event.payment_id}
            )

        def _json(self, status: int, payload: Json) -> None:
            data = (json.dumps(payload) + "\n").encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


def serve(
    secret: str,
    credit: CreditFn,
    *,
    host: str = "127.0.0.1",
    port: int = 8790,
    forever: bool = True,
) -> ThreadingHTTPServer:
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ConfigError("settle webhook must bind loopback (put a reverse proxy in front)")
    server = ThreadingHTTPServer((host, port), make_handler(secret, credit))
    if forever:
        server.serve_forever()
    return server
