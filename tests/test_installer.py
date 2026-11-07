from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "deploy" / "install.sh"
ATTACH = Path(__file__).resolve().parent.parent / "deploy" / "attach-domain.sh"
ROOTIT = Path(__file__).resolve().parent.parent / "deploy" / "install-rootit.sh"


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
    for script in (SCRIPT, ATTACH, ROOTIT):
        try:
            result = subprocess.run(
                [bash, "-n", str(script)], capture_output=True, check=False, timeout=20
            )
        except OSError:
            pytest.skip("bash is not usable here")
        if b"\x00" in result.stdout + result.stderr:
            pytest.skip("bash is only the WSL launcher stub (no distribution installed)")
        assert result.returncode == 0, f"{script.name}: {result.stderr.decode(errors='replace')}"


def test_rootit_installer_is_pasarguard_backed() -> None:
    text = ROOTIT.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "\r" not in text
    assert "set -Eeuo pipefail" in text
    assert "SHAHRAH_PANEL_API_KEY" in text
    assert "rootit init" in text
    assert "PasarGuard" in text


def test_attach_domain_is_dry_run_by_default() -> None:
    text = ATTACH.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "\r" not in text
    assert "--apply" in text
    assert "cdn-xhttp" in text
    assert "example.com" in text  # placeholders only
    assert "set -euo pipefail" in text


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
    assert (
        "grep -vE '\"xray\"|shahrah-xray'" in text
    )  # re-running must not mistake our own Xray for a conflict
    assert "preinstall_record_unit" in text
    assert "enforce_control_plane" in text


def test_beta_ops_scripts_are_syntactically_valid() -> None:
    root = Path(__file__).resolve().parents[1]
    scripts = (
        "deploy/beta/germany-attach-waterwall.sh",
        "deploy/beta/iran-relay-install.sh",
        "deploy/beta/migrate-exit-public-ip.sh",
        "deploy/beta/firewall-germany-beta.sh",
        "deploy/beta/firewall-iran-relay.sh",
        "scripts/backup-shahrah-bundle.sh",
        "scripts/restore-shahrah-drill.sh",
    )
    for rel in scripts:
        subprocess.run(["bash", "-n", str(root / rel)], check=True)


ARP = (
    "IP address       HW type     Flags       HW address            Mask     Device\n"
    "10.0.0.9         0x1         0x0         00:00:00:00:00:00     *        eth0\n"
    "10.0.0.1         0x1         0x2         AA:BB:CC:00:11:22     *        eth0\n"
)
ROUTE = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
    "eth0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\n"
)


def _source_and_run(tmp_path: Path, snippet: str) -> subprocess.CompletedProcess[str]:
    bash = _find_bash()
    if bash is None or not Path(bash).exists() or "System32" in bash:
        pytest.skip("bash not available")
    (tmp_path / "arp").write_text(ARP)
    (tmp_path / "route").write_text(ROUTE)
    script = (
        f"export ARP_TABLE='{(tmp_path / 'arp').as_posix()}' "
        f"ROUTE_TABLE='{(tmp_path / 'route').as_posix()}'\n"
        f"source '{SCRIPT.as_posix()}'\n"
        "ip() { return 0; }; ping() { return 1; }; arping() { return 1; }\n" + snippet
    )
    try:
        return subprocess.run(
            [bash, "-c", script], capture_output=True, text=True, check=False, timeout=20
        )
    except OSError:
        pytest.skip("bash is not usable here")


def test_gateway_discovery_falls_back_to_proc_tables(tmp_path: Path) -> None:
    """No `ip route`/`ip neigh`/arping answer: /proc/net/route and /proc/net/arp still work."""
    result = _source_and_run(
        tmp_path,
        'i="$(default_iface)"; g="$(default_gateway "$i")"; m="$(gateway_mac "$g" "$i")"\n'
        'echo "$i $g $m"',
    )
    if "\x00" in result.stdout + result.stderr:
        pytest.skip("bash is only the WSL launcher stub")
    assert result.stdout.split() == ["eth0", "10.0.0.1", "aa:bb:cc:00:11:22"], result.stderr


def test_gateway_mac_override_and_rejects_garbage(tmp_path: Path) -> None:
    result = _source_and_run(
        tmp_path,
        "PAQET_ROUTER_MAC=AA:AA:AA:AA:AA:01 gateway_mac 10.0.0.1 eth0\n"
        "PAQET_ROUTER_MAC=nonsense gateway_mac 10.0.0.1 eth0 || echo rejected",
    )
    if "\x00" in result.stdout + result.stderr:
        pytest.skip("bash is only the WSL launcher stub")
    assert result.stdout.split() == ["aa:aa:aa:aa:aa:01", "rejected"], result.stderr


def test_new_data_planes_are_pinned(text: str) -> None:
    for name in ("HY2_SHA256_AMD64", "HY2_SHA256_ARM64", "WW_SHA256_X64", "WW_SHA256_ARM64"):
        value = re.search(rf'{name}="([0-9a-f]*)"', text)
        assert value and len(value.group(1)) == 64, name
    for flag in (
        "--with-hysteria2",
        "--hy2-hop",
        "--with-warp",
        "--warp-route-all",
        "--with-waterwall",
        "--ww-peer",
        "relay",
    ):
        assert flag in text
