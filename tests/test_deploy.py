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
