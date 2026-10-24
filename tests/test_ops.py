from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from shahrah import ops
from shahrah.cli import main
from shahrah.models import ConfigError
from shahrah.sni_scout import ScoutResult

_TOKEN = "t" * 16
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def test_token_and_bind_guards() -> None:
    with pytest.raises(ConfigError, match="16"):
        ops.OpsConfig(token="short")
    with pytest.raises(ConfigError, match="loopback"):
        ops.OpsConfig(token="x" * 16, host="203.0.113.9")


def test_ops_requires_token_and_runs_scout(tmp_path) -> None:
    calls: list[list[str]] = []

    def fake_scout(hosts: list[str]) -> list[ScoutResult]:
        calls.append(hosts)
        return [ScoutResult(hosts[0], True, 9.0, "TLSv1.3", "h2", "ok")]

    status_file = tmp_path / "brain.json"
    status_file.write_text(json.dumps({"mode": "normal", "active": "exit-443"}), encoding="utf-8")
    config = ops.OpsConfig(
        token=_TOKEN,
        host="127.0.0.1",
        port=0,
        brain_status_path=str(status_file),
        scout=fake_scout,
    )
    server = ThreadingHTTPServer((config.host, 0), ops.make_handler(config))
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with pytest.raises(urllib.error.HTTPError) as denied:
            _OPENER.open(f"http://127.0.0.1:{port}/api/status", timeout=3)
        assert denied.value.code == 401

        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/status",
            headers={"X-Ops-Token": config.token},
        )
        with _OPENER.open(req, timeout=3) as response:
            body = json.loads(response.read().decode())
        assert body["brain"]["active"] == "exit-443"
        assert body["modules"]["sni_watch"] == "planned"
        assert body["modules"]["ig_mult"] == "planned"

        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/sni-scout",
            data=json.dumps({"hosts": ["www.example.com"]}).encode(),
            headers={"X-Ops-Token": config.token, "Content-Type": "application/json"},
            method="POST",
        )
        with _OPENER.open(req, timeout=3) as response:
            scout_body = json.loads(response.read().decode())
        assert scout_body["ranking"] == ["www.example.com"]
        assert calls == [["www.example.com"]]
    finally:
        server.shutdown()


def test_print_token_cli(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["ops", "--print-token"]) == 0
    token = capsys.readouterr().out.strip()
    assert len(token) >= 16
