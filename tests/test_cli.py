from __future__ import annotations

import base64
import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from shahrah.cli import main
from shahrah.state import load_state


@pytest.fixture
def state_file(tmp_path: Path) -> Path:
    return tmp_path / "state.json"


def run(state: Path, *args: str) -> int:
    return main(["--state", str(state), *args])


def init(state: Path) -> None:
    assert run(state, "init", "--host", "vpn.example.org", "--target", "www.cloudflare.com") == 0


def test_reconfigure_updates_host_without_rotating_keys(
    state_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    init(state_file)
    priv = load_state(state_file).private_key
    assert (
        run(
            state_file,
            "reconfigure",
            "--public-host",
            "198.51.100.221",
            "--target",
            "www.cloudflare.com",
        )
        == 0
    )
    st = load_state(state_file)
    assert st.public_host == "198.51.100.221"
    assert st.private_key == priv
    assert "preserved" in capsys.readouterr().out


def test_uninstall_plan_json_paths_are_scoped(
    state_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(state_file, "uninstall-plan", "--purge", "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert "/etc/shahrah" in data["paths"]
    assert all(not str(p).startswith("/etc/ssh") for p in data["paths"])


def test_init_refuses_to_overwrite_without_force(
    state_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    init(state_file)
    first_key = load_state(state_file).private_key
    assert run(state_file, "init", "--host", "a.example.org", "--target", "www.cloudflare.com") == 2
    assert "already exists" in capsys.readouterr().err
    assert load_state(state_file).private_key == first_key
    forced = run(
        state_file, "init", "--host", "a.example.org", "--target", "www.cloudflare.com", "--force"
    )
    assert forced == 0
    assert load_state(state_file).private_key != first_key


def test_init_output_never_prints_private_key(
    state_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    init(state_file)
    assert load_state(state_file).private_key not in capsys.readouterr().out


def test_init_rejects_risky_target(state_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = run(state_file, "init", "--host", "vpn.example.org", "--target", "www.apple.com")
    assert code == 2
    assert "blocked" in capsys.readouterr().err
    assert not state_file.exists()


def test_user_lifecycle_and_subscription(
    state_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    init(state_file)
    assert run(state_file, "user", "add", "alice") == 0
    capsys.readouterr()
    assert run(state_file, "user", "list") == 0
    assert capsys.readouterr().out.startswith("alice ")

    assert run(state_file, "link", "alice") == 0
    link = capsys.readouterr().out.strip()
    assert link.startswith("vless://") and "security=reality" in link
    assert "vpn.example.org" in link

    assert run(state_file, "sub", "alice") == 0
    body = base64.b64decode(capsys.readouterr().out.strip()).decode()
    assert body.strip() == link

    assert run(state_file, "user", "remove", "alice") == 0
    assert run(state_file, "link", "alice") == 2


def test_apply_requires_users(state_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    init(state_file)
    assert (
        run(state_file, "apply", "--no-validate", "--config-out", str(state_file.parent / "x")) == 2
    )
    assert "no users" in capsys.readouterr().err


def test_apply_writes_config_without_leaking_state_secrets_elsewhere(
    state_file: Path, tmp_path: Path
) -> None:
    init(state_file)
    run(state_file, "user", "add", "alice")
    out = tmp_path / "xray.json"
    assert run(state_file, "apply", "--no-validate", "--config-out", str(out)) == 0
    config = json.loads(out.read_text())
    state = load_state(state_file)
    inbound = config["inbounds"][0]
    assert inbound["settings"]["clients"][0]["id"] == state.users[0].uuid
    assert inbound["streamSettings"]["realitySettings"]["privateKey"] == state.private_key


def test_apply_validates_with_real_xray(state_file: Path, tmp_path: Path, xray_bin: str) -> None:
    init(state_file)
    run(state_file, "user", "add", "alice")
    out = tmp_path / "xray.json"
    assert run(state_file, "apply", "--xray-bin", xray_bin, "--config-out", str(out)) == 0
    assert out.exists()


def test_apply_with_missing_binary_does_not_write(
    state_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    init(state_file)
    run(state_file, "user", "add", "alice")
    out = tmp_path / "xray.json"
    code = run(state_file, "apply", "--xray-bin", "no-such-xray-binary", "--config-out", str(out))
    assert code == 2
    assert "not found" in capsys.readouterr().err
    assert not out.exists()


def test_print_helpers(state_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    init(state_file)
    assert run(state_file, "print", "systemd-unit") == 0
    assert "ExecStart=" in capsys.readouterr().out
    assert run(state_file, "print", "ufw", "--ssh-port", "2222") == 0
    assert "ufw allow 2222/tcp" in capsys.readouterr().out
    assert run(state_file, "print", "sysctl") == 0
    assert "bbr" in capsys.readouterr().out


def test_brain_once_reports_unreachable_path_as_degraded_with_real_xray(
    tmp_path: Path,
    xray_bin: str,
    real_keypair: tuple[str, str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    import socket

    with socket.socket() as sock:  # a port nothing listens on
        sock.bind(("127.0.0.1", 0))
        dead_port = sock.getsockname()[1]
    config = {
        "endpoints": [
            {
                "name": "nowhere",
                "host": "127.0.0.1",
                "port": dead_port,
                "profile": "reality-vision",
                "public_key": real_keypair[1],
                "short_id": "ab12",
                "sni": "www.cloudflare.com",
            }
        ],
        "probe_user": {"uuid": "5c1b2e0a-6f1d-4f43-9a38-3a3c9a4f9b11", "label": "probe"},
    }
    path = tmp_path / "brain.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    code = main(["brain", "--config", str(path), "--xray-bin", xray_bin, "--once"])
    assert code == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["ranking"] == []  # the dead path is not ranked
    assert summary["active"] is None


def test_panel_bootstrap_and_sales_role_against_a_panel(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests.test_panel import FakePanel

    fake = FakePanel([])
    try:
        monkeypatch.setenv("SHAHRAH_PANEL_API_KEY", FakePanel.API_KEY)
        common = ["panel", "--panel-url", fake.url]
        assert main([*common, "bootstrap", "--probe-group-id", "1", "2"]) == 0
        first = json.loads(capsys.readouterr().out)
        assert first["brain_role"] == "created"
        assert first["probe_user_state"] == "created"
        probe_uuid = first["probe_user"]["uuid"]
        assert fake.users["shahrah_probe"]["proxy_settings"]["vless"]["id"] == probe_uuid

        # Re-running is safe and keeps the same account.
        again = ["bootstrap", "--probe-group-id", "1", "--probe-uuid", probe_uuid]
        assert main([*common, *again]) == 0
        assert json.loads(capsys.readouterr().out)["probe_user_state"] == "already existed"

        assert main([*common, "sales-role", "--name", "sales-a", "--template-id", "3"]) == 0
        assert json.loads(capsys.readouterr().out)["sales_role"] == "created"
        assert {role["name"] for role in fake.roles} == {"shahrah-brain", "sales-a"}
    finally:
        fake.close()


def test_panel_command_needs_a_url(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("SHAHRAH_PANEL_URL", raising=False)
    code = main(["panel", "bootstrap", "--probe-group-id", "1"])
    assert code == 2
    assert "panel-url" in capsys.readouterr().err


def test_panel_wrong_key_is_reported_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests.test_panel import FakePanel

    fake = FakePanel([])
    try:
        monkeypatch.setenv("SHAHRAH_PANEL_API_KEY", "nope")
        code = main(["panel", "--panel-url", fake.url, "bootstrap", "--probe-group-id", "1"])
        assert code == 2
        assert "401" in capsys.readouterr().err
    finally:
        fake.close()


def test_cli_uploads_the_leak_resistant_template(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests.test_panel import FakePanel

    fake = FakePanel([])
    try:
        monkeypatch.setenv("SHAHRAH_PANEL_API_KEY", FakePanel.API_KEY)
        assert main(["panel", "--panel-url", fake.url, "client-template"]) == 0
        assert json.loads(capsys.readouterr().out) == {
            "client_template": "created",
            "is_default": False,
        }
        content = json.loads(fake.templates[0]["content"])
        assert content["dns"]["disableFallback"] is True
        assert content["routing"]["domainStrategy"] == "AsIs"
    finally:
        fake.close()


def test_multi_port_node_end_to_end_through_the_cli(
    state_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = run(
        state_file,
        "init",
        "--host",
        "vpn.example.org",
        "--target",
        "www.cloudflare.com",
        "--extra-listener",
        "80:reality-xhttp",
        "--extra-listener",
        "53:reality-xhttp",
    )
    assert code == 0
    run(state_file, "user", "add", "alice")
    capsys.readouterr()

    assert run(state_file, "link", "alice") == 0
    links = capsys.readouterr().out.strip().splitlines()
    assert [urlsplit(link).port for link in links] == [443, 80, 53]  # crisis order
    assert "type=xhttp" in links[1]
    assert "flow=xtls-rprx-vision" in links[0]

    assert run(state_file, "sub", "alice") == 0
    body = base64.b64decode(capsys.readouterr().out.strip()).decode().splitlines()
    assert [urlsplit(link).port for link in body] == [443, 80, 53]

    assert run(state_file, "print", "ufw") == 0
    firewall = capsys.readouterr().out
    assert all(f"ufw allow {port}/tcp" in firewall for port in (443, 80, 53))


def test_listener_commands_and_bad_spec(
    state_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    init(state_file)
    assert run(state_file, "listener", "add", "80:reality-xhttp") == 0
    assert "80 reality-xhttp" in capsys.readouterr().out
    assert run(state_file, "listener", "remove", "80") == 0
    assert run(state_file, "listener", "add", "eighty:reality-xhttp") == 2
    assert "PORT:PROFILE" in capsys.readouterr().err
    assert run(state_file, "listener", "add", "9999:reality-xhttp") == 2  # not a crisis port


def test_on_burn_hook_must_be_an_existing_executable(tmp_path: Path) -> None:
    from shahrah.cli import _burn_hook
    from shahrah.models import ConfigError

    with pytest.raises(ConfigError, match="executable"):
        _burn_hook(tmp_path / "nope.sh")


def test_rotate_reality_changes_keys_and_keeps_users(
    state_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    init(state_file)
    assert run(state_file, "user", "add", "alice") == 0
    before = json.loads(state_file.read_text(encoding="utf-8"))
    capsys.readouterr()
    assert run(state_file, "rotate-reality") == 0
    out = capsys.readouterr().out
    after = json.loads(state_file.read_text(encoding="utf-8"))
    assert after["private_key"] != before["private_key"]
    assert after["public_key"] != before["public_key"]
    assert after["short_ids"] != before["short_ids"]
    assert after["users"] == before["users"]
    assert "new public key:" in out and after["private_key"] not in out


def test_retarget_updates_sni(state_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    init(state_file)
    assert run(state_file, "retarget", "www.samsung.com") == 0
    assert "www.samsung.com" in capsys.readouterr().out
    assert json.loads(state_file.read_text(encoding="utf-8"))["target_host"] == "www.samsung.com"
    assert run(state_file, "retarget", "www.apple.com") == 2
