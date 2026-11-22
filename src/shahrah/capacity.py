"""Capacity planning for independent Shahrah exits (~1k-3k concurrent users).

These are **operator guidance** numbers derived from Xray's per-connection buffer,
keepalive, and typical social/AI traffic (not gaming). They do not replace a real
load test on production-sized hardware.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import ConfigError, Tuning


@dataclass(frozen=True, slots=True)
class CapacityPlan:
    users: int
    tuning: Tuning
    # Rough RSS estimate for the Xray process alone (buffers dominate).
    xray_rss_mb: int
    # Recommended VPS RAM so the OS + panel/brain still breathe.
    vps_ram_mb: int
    notes: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "users": self.users,
            "tuning": {
                "conn_idle_s": self.tuning.conn_idle_s,
                "handshake_s": self.tuning.handshake_s,
                "buffer_size_kb": self.tuning.buffer_size_kb,
                "tcp_keepalive_idle_s": self.tuning.tcp_keepalive_idle_s,
                "tcp_keepalive_interval_s": self.tuning.tcp_keepalive_interval_s,
            },
            "xray_rss_mb": self.xray_rss_mb,
            "vps_ram_mb": self.vps_ram_mb,
            "notes": list(self.notes),
        }


def plan_for_users(users: int) -> CapacityPlan:
    """Return tuning and memory guidance for ``users`` concurrent tunnels.

    Assumptions: mostly HTTPS/social/AI, REALITY+Vision or XHTTP, one mid-size exit.
    """
    if not isinstance(users, int) or isinstance(users, bool) or users < 1:
        raise ConfigError("users must be a positive integer")
    if users > 50_000:
        raise ConfigError("users looks unrealistic for a single exit; split the fleet")

    # Smaller buffers at higher concurrency; never below the model minimum (4 KiB).
    if users <= 500:
        buffer_kb = 128
        idle = 300
    elif users <= 1500:
        buffer_kb = 64
        idle = 240
    elif users <= 3000:
        buffer_kb = 32
        idle = 180
    else:
        buffer_kb = 16
        idle = 120

    tuning = Tuning(
        conn_idle_s=idle,
        handshake_s=4,
        buffer_size_kb=buffer_kb,
        tcp_keepalive_idle_s=30,
        tcp_keepalive_interval_s=15,
    )
    # Empirically Xray holds roughly buffer + ~50 KiB metadata per active conn.
    per_conn_kb = buffer_kb + 50
    xray_rss_mb = max(256, (users * per_conn_kb) // 1024 + 128)
    vps_ram_mb = max(2048, xray_rss_mb * 2 + 512)
    notes = (
        "Apply `shahrah print sysctl` and raise `LimitNOFILE` (installer already sets 1048576).",
        "Pick a REALITY cover site that is fast from the *exit* (handshake is per new conn).",
        "Idle/keepalive reaping is what prevents dead mobile connections from filling RAM.",
        "Lab 2 GiB boxes are for functional tests only; use vps_ram_mb for production sizing.",
    )
    return CapacityPlan(users, tuning, xray_rss_mb, vps_ram_mb, notes)
