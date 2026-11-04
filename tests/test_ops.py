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

    def fake_scout(hosts: list[str], **kwargs: object) -> list[ScoutResult]:
        calls.append(hosts)
        name = hosts[0] if hosts else "default.example"
        return [ScoutResult(name, True, 9.0, "TLSv1.3", "h2", "ok", ("reality",))]

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
        assert body["modules"]["sni_watch"] == "cli-ready"
        assert body["modules"]["ig_mult"] == "cli-ready"

        with pytest.raises(urllib.error.HTTPError) as watch_denied:
            watch_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/sni-watch",
                headers={"X-Ops-Token": config.token},
            )
            _OPENER.open(watch_req, timeout=3)
        assert watch_denied.value.code == 503

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


def test_ops_usage_from_injected_fn() -> None:
    from shahrah.accounting import UserTraffic

    config = ops.OpsConfig(
        token=_TOKEN,
        host="127.0.0.1",
        usage=lambda: {"alice": UserTraffic("alice", 10, 20)},
    )
    server = ThreadingHTTPServer((config.host, 0), ops.make_handler(config))
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/status",
            headers={"X-Ops-Token": config.token},
        )
        with _OPENER.open(req, timeout=3) as response:
            assert json.loads(response.read().decode())["modules"]["usage"] == "ready"
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/usage",
            headers={"X-Ops-Token": config.token},
        )
        with _OPENER.open(req, timeout=3) as response:
            body = json.loads(response.read().decode())
        assert body["alice"]["total"] == 30
    finally:
        server.shutdown()


def test_ops_sni_watch_from_access_log(tmp_path) -> None:
    import time

    log = tmp_path / "access.log"
    ts = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())
    log.write_text(
        f"{ts}.1 from 198.51.100.1:1 accepted tcp:instagram.com:443 email: alice\n",
        encoding="utf-8",
    )
    config = ops.OpsConfig(
        token=_TOKEN,
        host="127.0.0.1",
        access_log_path=str(log),
        retention_hours=1.0,
    )
    server = ThreadingHTTPServer((config.host, 0), ops.make_handler(config))
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/status",
            headers={"X-Ops-Token": config.token},
        )
        with _OPENER.open(req, timeout=3) as response:
            assert json.loads(response.read().decode())["modules"]["sni_watch"] == "ready"
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/sni-watch",
            headers={"X-Ops-Token": config.token},
        )
        with _OPENER.open(req, timeout=3) as response:
            body = json.loads(response.read().decode())
        assert body["by_user"]["alice"]["instagram.com"] == 1
    finally:
        server.shutdown()


def test_ops_ig_mult_get_put_and_estimate(tmp_path) -> None:
    import time

    from shahrah.accounting import UserTraffic

    log = tmp_path / "access.log"
    ts = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())
    log.write_text(
        f"{ts}.1 from 198.51.100.1:1 accepted tcp:www.instagram.com:443 email: alice\n"
        f"{ts}.2 from 198.51.100.1:1 accepted tcp:api.example.com:443 email: alice\n",
        encoding="utf-8",
    )
    cfg_path = tmp_path / "ig.json"
    config = ops.OpsConfig(
        token=_TOKEN,
        host="127.0.0.1",
        access_log_path=str(log),
        ig_mult_path=str(cfg_path),
        usage=lambda: {"alice": UserTraffic("alice", 1000, 1000)},
    )
    server = ThreadingHTTPServer((config.host, 0), ops.make_handler(config))
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/status",
            headers={"X-Ops-Token": config.token},
        )
        with _OPENER.open(req, timeout=3) as response:
            assert json.loads(response.read().decode())["modules"]["ig_mult"] == "ready"

        put = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/ig-mult",
            data=json.dumps({"enabled": True, "coefficient": 0.5}).encode(),
            headers={"X-Ops-Token": config.token, "Content-Type": "application/json"},
            method="PUT",
        )
        with _OPENER.open(put, timeout=3) as response:
            saved = json.loads(response.read().decode())
        assert saved["config"]["enabled"] is True
        assert saved["config"]["coefficient"] == 0.5

        est = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/ig-mult?estimate=1",
            headers={"X-Ops-Token": config.token},
        )
        with _OPENER.open(est, timeout=3) as response:
            body = json.loads(response.read().decode())
        # 1 of 2 hits is Instagram -> share 0.5; factor = 0.5 + 0.5*0.5 = 0.75
        assert body["users"]["alice"]["billed_uplink"] == 750
    finally:
        server.shutdown()


def test_print_token_cli(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["ops", "--print-token"]) == 0
    token = capsys.readouterr().out.strip()
    assert len(token) >= 16
