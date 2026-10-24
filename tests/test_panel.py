from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from shahrah.models import ConfigError
from shahrah.panel import PanelClient, PanelError, SyncPlan, apply_plan, plan_sync, sync

REMARKS = {"exit-a": "Exit A", "exit-b": "Exit B", "cdn": "CDN"}


def host(host_id: int, remark: str, *, disabled: bool = False, priority: int = 0) -> dict[str, Any]:
    return {"id": host_id, "remark": remark, "is_disabled": disabled, "priority": priority}


# ------------------------------------------------------------------------------- planning


def test_everything_healthy_and_in_order_is_a_no_op() -> None:
    hosts = [
        host(1, "Exit A", priority=0),
        host(2, "Exit B", priority=1),
        host(3, "CDN", priority=2),
    ]
    plan = plan_sync(hosts, ["exit-a", "exit-b", "cdn"], REMARKS)
    assert plan.empty
    assert plan.skipped_reason is None


def test_unhealthy_hosts_are_disabled_and_healthy_ones_reordered() -> None:
    hosts = [
        host(1, "Exit A", priority=0),
        host(2, "Exit B", priority=1),
        host(3, "CDN", priority=2),
    ]
    plan = plan_sync(hosts, ["cdn", "exit-b"], REMARKS)  # exit-a is down
    assert plan.disable == (1,)
    assert plan.enable == ()
    assert plan.priorities == {3: 0}  # exit-b already has priority 1: no redundant write


def test_recovered_host_is_re_enabled() -> None:
    hosts = [host(1, "Exit A", disabled=True, priority=5), host(2, "Exit B", priority=1)]
    plan = plan_sync(hosts, ["exit-b", "exit-a"], {"exit-a": "Exit A", "exit-b": "Exit B"})
    assert plan.enable == (1,)
    assert plan.priorities == {2: 0, 1: 1}


def test_no_healthy_path_fails_open_and_changes_nothing() -> None:
    hosts = [host(1, "Exit A"), host(2, "Exit B"), host(3, "CDN")]
    plan = plan_sync(hosts, [], REMARKS)
    assert plan.empty
    assert plan.skipped_reason is not None


def test_unmapped_hosts_are_never_touched() -> None:
    hosts = [host(1, "Exit A"), host(9, "Manually managed", priority=7)]
    plan = plan_sync(hosts, ["exit-a"], {"exit-a": "Exit A"})
    assert 9 not in plan.disable
    assert 9 not in plan.enable
    assert 9 not in plan.priorities


def test_missing_host_in_panel_is_a_configuration_error() -> None:
    with pytest.raises(ConfigError, match="no host with remark"):
        plan_sync([host(1, "Exit A")], ["exit-a"], REMARKS)


def test_duplicate_remarks_are_rejected_because_mapping_would_be_ambiguous() -> None:
    with pytest.raises(ConfigError, match="duplicate"):
        plan_sync([host(1, "Exit A"), host(2, "Exit A")], ["exit-a"], {"exit-a": "Exit A"})


# ------------------------------------------------------------------------------ the client


def test_client_refuses_plain_http_to_remote_hosts() -> None:
    with pytest.raises(ConfigError, match="plain http"):
        PanelClient("http://panel.example.org", "key")
    PanelClient("http://127.0.0.1:8000", "key")  # loopback is fine
    PanelClient("http://panel.example.org", "key", allow_insecure_http=True)


@pytest.mark.parametrize("url", ["panel.example.org", "ftp://panel.example.org", "https://"])
def test_client_rejects_malformed_urls(url: str) -> None:
    with pytest.raises(ConfigError, match="panel url"):
        PanelClient(url, "key")


def test_client_rejects_empty_key_and_never_prints_it() -> None:
    with pytest.raises(ConfigError, match="api key"):
        PanelClient("https://panel.example.org", "  ")
    client = PanelClient("https://panel.example.org", "super-secret-key")
    assert "super-secret-key" not in repr(client)


# ------------------------------------------------- end-to-end against a fake HTTP panel


class FakePanel:
    """A tiny in-memory imitation of the PasarGuard host endpoints used by Shahrah."""

    API_KEY = "test-key"

    def __init__(self, hosts: list[dict[str, Any]]) -> None:
        self.hosts = {h["id"]: dict(h) for h in hosts}
        self.calls: list[tuple[str, str]] = []
        panel = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                return

            def _reply(self, status: int, payload: Any = None) -> None:
                body = json.dumps(payload).encode() if payload is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self) -> Any:
                length = int(self.headers.get("Content-Length", 0))
                return json.loads(self.rfile.read(length)) if length else None

            def _dispatch(self, method: str) -> None:
                if self.headers.get("X-Api-Key") != panel.API_KEY:
                    self._reply(401, {"detail": "bad key"})
                    return
                panel.calls.append((method, self.path))
                body = self._body()
                if method == "GET" and self.path == "/api/hosts":
                    self._reply(200, list(panel.hosts.values()))
                elif method == "GET" and self.path.startswith("/api/host/"):
                    self._reply(200, panel.hosts[int(self.path.rsplit("/", 1)[1])])
                elif method == "PUT" and self.path.startswith("/api/host/"):
                    host_id = int(self.path.rsplit("/", 1)[1])
                    panel.hosts[host_id].update(body)
                    self._reply(200, panel.hosts[host_id])
                elif method == "POST" and self.path in (
                    "/api/hosts/bulk/disable",
                    "/api/hosts/bulk/enable",
                ):
                    disabled = self.path.endswith("disable")
                    for host_id in body["ids"]:
                        panel.hosts[host_id]["is_disabled"] = disabled
                    self._reply(200, {"count": len(body["ids"])})
                else:
                    self._reply(404, {"detail": "not found"})

            def do_GET(self) -> None:
                self._dispatch("GET")

            def do_PUT(self) -> None:
                self._dispatch("PUT")

            def do_POST(self) -> None:
                self._dispatch("POST")

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def panel() -> Iterator[FakePanel]:
    fake = FakePanel(
        [
            {**host(1, "Exit A", priority=0), "address": ["a.example.org"], "port": 443},
            {**host(2, "Exit B", priority=1), "address": ["b.example.org"], "port": 443},
            {**host(3, "CDN", priority=2), "address": ["c.example.org"], "port": 443},
        ]
    )
    yield fake
    fake.close()


def test_sync_applies_ranking_through_real_http(panel: FakePanel) -> None:
    client = PanelClient(panel.url, FakePanel.API_KEY)
    plan = sync(client, ["cdn", "exit-b"], REMARKS)  # exit-a is down
    assert plan.disable == (1,)
    assert panel.hosts[1]["is_disabled"] is True
    assert panel.hosts[2]["is_disabled"] is False
    assert (panel.hosts[3]["priority"], panel.hosts[2]["priority"]) == (0, 1)
    # Read-modify-write must not drop fields the panel requires.
    assert panel.hosts[3]["address"] == ["c.example.org"]
    assert panel.hosts[3]["port"] == 443


def test_second_sync_is_idempotent_and_sends_no_writes(panel: FakePanel) -> None:
    client = PanelClient(panel.url, FakePanel.API_KEY)
    sync(client, ["cdn", "exit-b"], REMARKS)
    panel.calls.clear()
    plan = sync(client, ["cdn", "exit-b"], REMARKS)
    assert plan.empty
    assert [method for method, _ in panel.calls] == ["GET"]


def test_enabling_happens_before_disabling(panel: FakePanel) -> None:
    panel.hosts[1]["is_disabled"] = True
    client = PanelClient(panel.url, FakePanel.API_KEY)
    panel.calls.clear()
    apply_plan(client, SyncPlan(enable=(1,), disable=(2,), priorities={}))
    assert [path for _, path in panel.calls] == [
        "/api/hosts/bulk/enable",
        "/api/hosts/bulk/disable",
    ]


def test_wrong_api_key_raises_panel_error_without_leaking_it(panel: FakePanel) -> None:
    client = PanelClient(panel.url, "wrong-key-123")
    with pytest.raises(PanelError, match="HTTP 401") as info:
        client.list_hosts()
    assert "wrong-key-123" not in str(info.value)


def test_unreachable_panel_is_reported_cleanly() -> None:
    client = PanelClient("http://127.0.0.1:9", "key")  # discard port: nothing listens
    with pytest.raises(PanelError, match="unreachable"):
        client.list_hosts()
