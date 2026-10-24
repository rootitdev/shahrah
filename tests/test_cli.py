from __future__ import annotations

import base64
import json
from pathlib import Path

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
