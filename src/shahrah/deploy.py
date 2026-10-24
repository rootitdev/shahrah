"""Pure generators for the host-level files a node needs (systemd unit, firewall, sysctl).

Nothing here touches the machine: the installer script decides when to apply them. Keeping
them as functions makes the security-relevant output (hardening flags, firewall order)
unit-testable on any OS.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import PurePosixPath

from .models import ConfigError, validate_port

SERVICE_USER = "shahrah"
DEFAULT_CONFIG_DIR = PurePosixPath("/etc/shahrah")
DEFAULT_XRAY_BIN = PurePosixPath("/usr/local/bin/xray")
DEFAULT_SHAHRAH_BIN = PurePosixPath("/usr/local/bin/shahrah")


def systemd_unit(
    *,
    xray_bin: PurePosixPath = DEFAULT_XRAY_BIN,
    config: PurePosixPath = DEFAULT_CONFIG_DIR / "xray.json",
    user: str = SERVICE_USER,
) -> str:
    """Hardened unit: unprivileged user, only the bind-low-port capability, read-only system."""
    return f"""[Unit]
Description=Xray core managed by shahrah
Documentation=https://github.com/XTLS/Xray-core
After=network-online.target
Wants=network-online.target

[Service]
User={user}
Group={user}
ExecStartPre={xray_bin} run -test -c {config}
ExecStart={xray_bin} run -c {config}
Restart=always
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
"""


def brain_unit(
    *,
    shahrah_bin: PurePosixPath = DEFAULT_SHAHRAH_BIN,
    xray_bin: PurePosixPath = DEFAULT_XRAY_BIN,
    config: PurePosixPath = DEFAULT_CONFIG_DIR / "brain.json",
    env_file: PurePosixPath = DEFAULT_CONFIG_DIR / "brain.env",
    user: str = SERVICE_USER,
) -> str:
    """The brain only makes outbound connections: no capabilities, no listening sockets."""
    return f"""[Unit]
Description=Shahrah brain (tunnel health prober and panel steering)
After=network-online.target
Wants=network-online.target

[Service]
User={user}
Group={user}
EnvironmentFile={env_file}
ExecStart={shahrah_bin} brain --config {config} --xray-bin {xray_bin}
Restart=always
RestartSec=10
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_INET AF_INET6
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
"""


def ufw_commands(*, ssh_port: int, public_ports: Iterable[int]) -> list[str]:
    """Firewall plan. SSH is allowed *before* enabling so the operator is never locked out."""
    validate_port(ssh_port, "ssh port")
    ports = sorted(set(public_ports))
    if not ports:
        raise ConfigError("at least one public port is required")
    for port in ports:
        validate_port(port, "public port")
    if ssh_port in ports:
        raise ConfigError("ssh port must not be one of the public VPN ports")
    commands = [
        "ufw default deny incoming",
        "ufw default allow outgoing",
        f"ufw allow {ssh_port}/tcp",
    ]
    commands += [f"ufw allow {port}/tcp" for port in ports]
    commands.append("ufw --force enable")
    return commands


def sysctl_conf() -> str:
    """Kernel settings for thousands of TCP flows; BBR helps lossy international links."""
    return """# Managed by shahrah
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_fastopen = 3
fs.file-max = 2097152
"""
