from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from shahrah import settle
from shahrah.cli import main
from shahrah.models import ConfigError
from shahrah.panel import PanelClient

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def test_sign_and_parse_roundtrip() -> None:
    body = json.dumps(
        {"username": "alice", "add_expire_s": 86400, "add_bytes": 0, "payment_id": "p1"}
    ).encode()
    secret = "s" * 16
    sig = settle.sign_body(secret, body)
    assert settle.verify_signature(secret, body, sig)
    event = settle.parse_event(json.loads(body))
    assert event.username == "alice" and event.add_expire_s == 86400


def test_parse_rejects_empty_credit() -> None:
    with pytest.raises(ConfigError, match="credit"):
        settle.parse_event({"username": "alice"})


def test_parse_provider_aliases_and_signed_request() -> None:
    event = settle.parse_event({"username": "alice", "days": 7, "traffic_gb": 1})
    assert event.add_expire_s == 7 * 86400
    assert event.add_bytes == 1024**3
    req = settle.signed_request("s" * 16, event)
    assert req["url"].endswith("/hooks/payment")
    assert settle.verify_signature("s" * 16, req["body"].encode(), req["signature"])


def test_credit_user_accepts_iso_expire() -> None:
    put: dict = {}

    def transport(method, url, headers, body):
        if method == "GET":
            return 200, {
                "username": "alice",
                "expire": "2026-10-25T19:13:09Z",
                "data_limit": 1_000_000,
            }
        put.update(json.loads(body.decode()))
        return 200, put

    client = PanelClient("https://127.0.0.1:8000", "k" * 16, transport=transport)
    result = settle.credit_user(client, settle.SettleEvent("alice", add_expire_s=86400))
    base = settle._as_unix_expire("2026-10-25T19:13:09Z")
    assert result["expire"] == put["expire"] == base + 86400


def test_webhook_rejects_bad_signature_and_credits_on_ok() -> None:
    credited: list[tuple[str, int, int]] = []

    def credit(username: str, add_expire_s: int, add_bytes: int) -> None:
        credited.append((username, add_expire_s, add_bytes))

    secret = "t" * 16
    server = ThreadingHTTPServer(("127.0.0.1", 0), settle.make_handler(secret, credit))
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        body = json.dumps({"username": "bob", "add_expire_s": 3600}).encode()
        with pytest.raises(urllib.error.HTTPError) as denied:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/hooks/payment",
                data=body,
                headers={"Content-Type": "application/json", "X-Shahrah-Signature": "dead"},
                method="POST",
            )
            _OPENER.open(req, timeout=3)
        assert denied.value.code == 401

        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/hooks/payment",
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Shahrah-Signature": settle.sign_body(secret, body),
            },
            method="POST",
        )
        with _OPENER.open(req, timeout=3) as response:
            assert json.loads(response.read().decode())["ok"] is True
        assert credited == [("bob", 3600, 0)]
    finally:
        server.shutdown()


def test_credit_user_extends_finite_quotas() -> None:
    calls: list[tuple[str, str]] = []

    def transport(method: str, url: str, headers, body):
        calls.append((method, url))
        if method == "GET" and url.endswith("/api/user/alice"):
            return 200, {"username": "alice", "expire": 1000, "data_limit": 1_000_000}
        if method == "PUT" and url.endswith("/api/user/alice"):
            return 200, json.loads(body.decode())
        return 404, {"detail": "no"}

    client = PanelClient("http://127.0.0.1:9", "k", allow_insecure_http=True, transport=transport)
    result = settle.credit_user(client, settle.SettleEvent("alice", add_expire_s=50, add_bytes=100))
    assert result["expire"] == 1050
    assert result["data_limit"] == 1_000_100
    assert ("PUT", "http://127.0.0.1:9/api/user/alice") in calls


def test_credit_refuses_unlimited() -> None:
    def transport(method: str, url: str, headers, body):
        return 200, {"username": "alice", "expire": 0, "data_limit": 0}

    client = PanelClient("http://127.0.0.1:9", "k", allow_insecure_http=True, transport=transport)
    with pytest.raises(ConfigError, match="unlimited-expiry"):
        settle.credit_user(client, settle.SettleEvent("alice", add_expire_s=10))


def test_print_settle_secret(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["settle-hook", "--print-secret"]) == 0
    assert len(capsys.readouterr().out.strip()) >= 16
