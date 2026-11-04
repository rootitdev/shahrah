from __future__ import annotations

import base64
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from shahrah import subserve
from shahrah.cli import main
from shahrah.state import NodeState, save_state

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_SECRET = "s" * 16


def test_serve_sub_returns_base64_links(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    state = NodeState.create(public_host="203.0.113.10", target_host="www.example.com")
    state, user = state.with_user("alice")
    save_state(state_path, state)
    server = ThreadingHTTPServer(("127.0.0.1", 0), subserve.make_handler(state_path, _SECRET))
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with _OPENER.open(f"http://127.0.0.1:{port}/{_SECRET}/alice", timeout=3) as response:
            body = response.read().decode()
        text = base64.b64decode(body).decode()
        assert "vless://" in text and user.uuid in text
        assert "203.0.113.10" in text
    finally:
        server.shutdown()


def test_print_secret_cli(capsys) -> None:
    assert main(["serve-sub", "--print-secret"]) == 0
    assert len(capsys.readouterr().out.strip()) >= 16
