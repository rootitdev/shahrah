from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "deploy" / "install.sh"


@pytest.fixture(scope="module")
def text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_script_is_strict_and_lf_only(text: str) -> None:
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "set -Eeuo pipefail" in text
    assert "\r" not in text


def test_pinned_checksums_are_well_formed(text: str) -> None:
    hashes = re.findall(r'PINNED_SHA256_\w+="([^"]*)"', text)
    assert len(hashes) == 2
    assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in hashes)
    assert len(set(hashes)) == 2


def test_binary_is_verified_before_install(text: str) -> None:
    assert text.index("sha256sum") < text.index("install -m 0755")
    assert "checksum mismatch" in text


def test_script_contains_no_private_infrastructure(text: str) -> None:
    ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    assert [ip for ip in ips if not ip.startswith("127.")] == []  # loopback is not infrastructure
    assert "rootitdev" not in text


def test_firewall_is_applied_after_the_service_is_verified(text: str) -> None:
    body = text[text.index("main() {") :]
    assert body.index("install_service") < body.index("setup_firewall")


def _find_bash() -> str | None:
    git_bash = Path("C:/Program Files/Git/bin/bash.exe")
    if git_bash.exists():
        return str(git_bash)
    return shutil.which("bash")


def test_bash_accepts_the_syntax() -> None:
    bash = _find_bash()
    if bash is None:
        pytest.skip("bash not available")
    try:
        result = subprocess.run(
            [bash, "-n", str(SCRIPT)], capture_output=True, check=False, timeout=20
        )
    except OSError:
        pytest.skip("bash is not usable here")
    if b"\x00" in result.stdout + result.stderr:
        pytest.skip("bash is only the WSL launcher stub (no distribution installed)")
    assert result.returncode == 0, result.stderr.decode(errors="replace")


def test_brain_role_keeps_secrets_out_of_the_world_readable_tree(text: str) -> None:
    assert "--role) ROLE=" in text
    section = text[text.index("install_brain() {") : text.index("detect_ssh_port() {")]
    assert "install -m 0640" in section  # readable by the service group, not world
    assert 'chown root:"$SERVICE_USER"' in section
    assert "brain.env" in section
    assert "ufw" not in section  # the brain opens no ports


def test_multi_port_options_reach_the_node_and_port_53_is_freed_first(text: str) -> None:
    assert "--multi-port) EXTRA_LISTENERS+=(" in text
    assert "--extra-listener) EXTRA_LISTENERS+=(" in text
    assert 'extra+=(--extra-listener "$spec")' in text
    body = text[text.index("main() {") :]
    assert "install_service" in body
    # the stub resolver is disabled inside install_service, before the service is (re)started
    service = text[text.index("install_service() {") : text.index("detect_ssh_port() {")]
    assert service.index("free_dns_port") < service.index("systemctl restart")
    assert "DNSStubListener=no" in text
    assert "grep -v '\"xray\"'" in text  # re-running must not mistake our own Xray for a conflict
