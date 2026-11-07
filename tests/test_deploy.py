from __future__ import annotations

import pytest

from shahrah import deploy
from shahrah.models import ConfigError


def test_systemd_unit_is_hardened_and_validates_before_start() -> None:
    unit = deploy.systemd_unit()
    assert "User=shahrah" in unit
    assert "NoNewPrivileges=true" in unit
    assert "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" in unit
    assert "ProtectSystem=strict" in unit
    pre = next(line for line in unit.splitlines() if line.startswith("ExecStartPre="))
    assert "run -test" in pre  # a bad config must never replace a working service
    assert "Restart=always" in unit
    assert "root" not in unit.lower().replace("wantedby", "")


def test_ufw_allows_ssh_before_enabling() -> None:
    commands = deploy.ufw_commands(ssh_port=22, public_ports=[443])
    assert commands.index("ufw allow 22/tcp") < commands.index("ufw --force enable")
    assert commands[0] == "ufw default deny incoming"
    assert "ufw allow 443/tcp" in commands
    assert not any("udp" in c for c in commands)  # UDP is dropped in the target environment


def test_ufw_rejects_ssh_on_public_port_and_empty_ports() -> None:
    with pytest.raises(ConfigError, match="ssh port"):
        deploy.ufw_commands(ssh_port=443, public_ports=[443])
    with pytest.raises(ConfigError, match="at least one"):
        deploy.ufw_commands(ssh_port=22, public_ports=[])


def test_sysctl_enables_bbr() -> None:
    conf = deploy.sysctl_conf()
    assert "tcp_congestion_control = bbr" in conf
    assert "default_qdisc = fq" in conf


def test_brain_unit_has_no_privileges_and_no_listening_sockets() -> None:
    unit = deploy.brain_unit()
    assert "brain --config /etc/shahrah/brain.json" in unit
    assert "EnvironmentFile=/etc/shahrah/brain.env" in unit  # the API key never sits in the unit
    assert "CapabilityBoundingSet=\n" in unit
    assert "NoNewPrivileges=true" in unit
    assert "RestrictAddressFamilies=AF_INET AF_INET6" in unit
    assert "CAP_NET_BIND_SERVICE" not in unit
    assert "User=shahrah" in unit
    assert "ReadWritePaths=/etc/shahrah" in unit


def test_serve_sub_unit_keeps_path_secret_out_of_argv() -> None:
    unit = deploy.serve_sub_unit()
    assert "EnvironmentFile=/etc/shahrah/sub.env" in unit
    assert "serve-sub --listen 127.0.0.1:8788" in unit
    assert "--path-secret" not in unit  # secret must not appear on the process command line
    assert "User=shahrah" in unit


def test_rootit_unit_keeps_panel_api_key_out_of_argv() -> None:
    unit = deploy.rootit_unit()
    assert "EnvironmentFile=/etc/shahrah/rootit.env" in unit
    assert "rootit serve --config /etc/shahrah/rootit.json" in unit
    assert "API_KEY" not in unit
    assert "User=shahrah" in unit
    assert "ReadWritePaths=/etc/shahrah" in unit


def test_sysctl_enables_mtu_probing_with_safe_base_mss() -> None:
    from shahrah.deploy import sysctl_conf

    text = sysctl_conf()
    assert "net.ipv4.tcp_mtu_probing = 2" in text
    assert "net.ipv4.tcp_base_mss = 1220" in text
