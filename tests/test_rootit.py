from __future__ import annotations

import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, build_opener

import pytest

from shahrah import rootit
from shahrah.cli import main
from shahrah.models import ConfigError
from shahrah.panel import PanelClient

_OPENER = build_opener()


def test_apply_public_base_rewrites_host_keeps_token() -> None:
    assert (
        rootit.apply_public_base(
            "https://panel.jetengine.ir:2096/sub/djMsNCwx.TOKEN",
            "https://panel.example.ir:2096",
        )
        == "https://panel.example.ir:2096/sub/djMsNCwx.TOKEN"
    )
    assert (
        rootit.apply_public_base("/sub/abc.TOKEN", "https://sub.example.com")
        == "https://sub.example.com/sub/abc.TOKEN"
    )


def test_pin_is_six_lowercase_alnum() -> None:
    pin = rootit.generate_pin()
    assert len(pin) == 6
    assert pin == pin.lower()
    assert rootit.validate_pin(pin) == pin
    with pytest.raises(ConfigError):
        rootit.validate_pin("ABCD12")
    with pytest.raises(ConfigError):
        rootit.validate_pin("ab12")


def test_password_roundtrip() -> None:
    encoded = rootit.hash_password("ab12cd", salt=b"\x00" * 16)
    assert rootit.verify_password("ab12cd", encoded)
    assert not rootit.verify_password("ab12ce", encoded)
    assert rootit.verify_password("ab12cd", "ab12cd")
    assert rootit.readable_pin("ab12cd") == "ab12cd"
    assert rootit.readable_pin(encoded) is None


def test_issue_pin_stores_plaintext(tmp_path: Path) -> None:
    cfg = rootit.default_config()
    cfg, pin = rootit.issue_pin(cfg, "ali")
    assert rootit.validate_pin(pin) == pin
    assert cfg.pins["ali"] == pin
    cfg2, pin2 = rootit.ensure_user_pin(cfg, "ali")
    assert pin2 == pin and cfg2 is cfg


def test_export_pins_csv() -> None:
    cfg = rootit.default_config()
    cfg, _ = rootit.issue_pin(cfg, "bob")
    cfg = rootit.set_pin(cfg, "ali", "ab12cd")
    csv = rootit.export_pins_csv(cfg)
    assert "username,pin" in csv
    assert "ali,ab12cd" in csv
    assert "bob," in csv


def test_admin_users_page_has_table_and_export() -> None:
    cfg = rootit.default_config()
    cfg = rootit.set_pin(cfg, "ali", "ab12cd")
    html = rootit._admin_users_page(cfg, page=1).decode()
    assert "ali" in html and "ab12cd" in html
    assert "/admin/export-pins" in html
    assert "کپی" in html


def test_config_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "rootit.json"
    cfg = rootit.RootitConfig.from_dict(
        {
            **rootit.default_config().as_dict(),
            "panel_url": "https://panel.example.com:8000",
            "public_host": "sub.example.com",
            "public_port": 2096,
            "require_password": False,
        }
    )
    rootit.save_config(path, cfg)
    loaded = rootit.load_config(path)
    assert loaded.base() == "https://sub.example.com:2096"
    assert loaded.panel_url.endswith(":8000")


def test_resolve_subscription_uses_pasarguard_client(tmp_path: Path) -> None:
    calls: list[tuple[str, str]] = []

    def transport(method: str, url: str, headers, body):  # noqa: ANN001
        calls.append((method, url))
        assert headers.get("X-Api-Key") == "test-key"
        assert url.endswith("/api/user/ali")
        return 200, {
            "username": "ali",
            "status": "active",
            "subscription_url": "https://old.example:2096/sub/tok.ALI",
        }

    cfg = rootit.RootitConfig.from_dict(
        {
            **rootit.default_config().as_dict(),
            "panel_url": "https://panel.example.com",
            "public_host": "new.example",
            "public_port": 443,
            "public_scheme": "https",
        }
    )
    client = PanelClient("https://panel.example.com", "test-key", transport=transport)
    url, user = rootit.resolve_subscription_url(client, cfg, "ali")
    assert url == "https://new.example/sub/tok.ALI"
    assert user["username"] == "ali"
    assert calls == [("GET", "https://panel.example.com/api/user/ali")]


def test_mysub_emergency_no_password(tmp_path: Path, monkeypatch) -> None:
    cfg_path = tmp_path / "rootit.json"
    cfg = rootit.RootitConfig.from_dict(
        {
            **rootit.default_config().as_dict(),
            "panel_url": "https://panel.example.com",
            "public_host": "sub.example.com",
            "public_port": 2096,
            "require_password": False,
        }
    )
    rootit.save_config(cfg_path, cfg)
    monkeypatch.setenv("SHAHRAH_PANEL_API_KEY", "k" * 32)

    def transport(method: str, url: str, headers, body):  # noqa: ANN001
        return 200, {
            "username": "ali",
            "status": "active",
            "subscription_url": "/sub/tok.ALI",
        }

    monkeypatch.setattr(
        rootit,
        "make_panel_client",
        lambda config, api_key=None: PanelClient(
            config.panel_url, "k" * 32, transport=transport, allow_insecure_http=True
        ),
    )

    server = ThreadingHTTPServer(("127.0.0.1", 0), rootit.make_handler(cfg_path))
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        body = "username=ali".encode()
        req = Request(
            f"http://127.0.0.1:{port}/mysub",
            data=body,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with _OPENER.open(req, timeout=5) as resp:
            html = resp.read().decode()
        assert "https://sub.example.com:2096/sub/tok.ALI" in html
        assert "tok.ALI" in html
        assert 'class="pinbig"' in html
        saved = rootit.load_config(cfg_path)
        assert "ali" in saved.pins
        assert rootit.readable_pin(saved.pins["ali"])
        assert saved.pins["ali"] in html
    finally:
        server.shutdown()


def test_admin_users_and_export_http(tmp_path: Path) -> None:
    cfg_path = tmp_path / "rootit.json"
    cfg = rootit.default_config()
    cfg = rootit.RootitConfig.from_dict(
        {
            **cfg.as_dict(),
            "admin_token": "tok-admin-test-32chars-xxxxxx",
            "panel_url": "https://panel.example.com",
            "public_host": "sub.example.com",
        }
    )
    cfg = rootit.set_pin(cfg, "ali", "ab12cd")
    rootit.save_config(cfg_path, cfg)

    server = ThreadingHTTPServer(("127.0.0.1", 0), rootit.make_handler(cfg_path))
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        req = Request(
            f"http://127.0.0.1:{port}/admin/users?admin_token=tok-admin-test-32chars-xxxxxx"
        )
        with _OPENER.open(req, timeout=5) as resp:
            html = resp.read().decode()
        assert "ali" in html and "ab12cd" in html
        req2 = Request(
            f"http://127.0.0.1:{port}/admin/export-pins?admin_token=tok-admin-test-32chars-xxxxxx"
        )
        with _OPENER.open(req2, timeout=5) as resp:
            csv = resp.read().decode()
        assert "ali,ab12cd" in csv
    finally:
        server.shutdown()


def test_cli_rootit_init_and_set_base(tmp_path: Path, capsys) -> None:
    path = tmp_path / "rootit.json"
    assert (
        main(
            [
                "rootit",
                "init",
                "--config",
                str(path),
                "--panel-url",
                "https://panel.example.com:8000",
                "--public-host",
                "old.example",
                "--public-port",
                "2096",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "admin_token=" in out
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["public_host"] == "old.example"
    assert (
        main(
            [
                "rootit",
                "set-base",
                "--config",
                str(path),
                "--host",
                "new.example",
                "--port",
                "443",
            ]
        )
        == 0
    )
    assert rootit.load_config(path).base() == "https://new.example"


def test_cli_print_rootit_unit(capsys) -> None:
    assert main(["print", "rootit-unit"]) == 0
    text = capsys.readouterr().out
    assert "rootit serve" in text
    assert "SHAHRAH_PANEL_API_KEY" not in text


def test_import_pins(tmp_path: Path) -> None:
    cfg = rootit.default_config()
    cfg, n = rootit.import_pins_lines(cfg, "ali|ab12cd\n# c\nbob|xy99zz\n")
    assert n == 2
    assert "ali" in cfg.pins and "bob" in cfg.pins
    with pytest.raises(ConfigError):
        rootit.import_pins_lines(cfg, "badline")
    with pytest.raises(ConfigError):
        rootit.import_pins_lines(cfg, "ali|SHORT")
