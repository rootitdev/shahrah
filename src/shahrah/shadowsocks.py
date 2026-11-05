"""Shadowsocks-2022 (blake3-aes-128-gcm) share links and Xray inbound fragments.

No VMess. SS2022 is the only legacy-cipher family Shahrah offers, as a UDP/TCP
crisis alternate on a scouted high port.
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from .models import ConfigError, User, is_ip, validate_host, validate_port

METHOD = "2022-blake3-aes-128-gcm"
# AES-128-GCM key material is 16 bytes; Xray expects standard base64.
_KEY_LEN = 16


def generate_server_password() -> str:
    return base64.b64encode(secrets.token_bytes(_KEY_LEN)).decode("ascii")


def generate_user_password() -> str:
    return base64.b64encode(secrets.token_bytes(_KEY_LEN)).decode("ascii")


@dataclass(frozen=True, slots=True)
class Ss2022Settings:
    port: int
    server_password: str  # base64 16 bytes
    # per-user passwords keyed by label (Xray multi-user 2022)
    user_passwords: dict[str, str]

    def __post_init__(self) -> None:
        validate_port(self.port, "ss2022 port")
        if self.port in {80, 443}:
            raise ConfigError("ss2022 must not use 80/443; pick a scouted high port")
        _check_b64_key(self.server_password, "ss2022 server password")
        if not self.user_passwords:
            raise ConfigError("ss2022 needs at least one user password")
        for label, pw in self.user_passwords.items():
            _check_b64_key(pw, f"ss2022 user password for {label}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "server_password": self.server_password,
            "user_passwords": dict(self.user_passwords),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Ss2022Settings:
        return cls(
            port=int(data["port"]),
            server_password=str(data["server_password"]),
            user_passwords={
                str(k): str(v) for k, v in dict(data.get("user_passwords") or {}).items()
            },
        )


def _check_b64_key(value: str, what: str) -> None:
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ConfigError(f"{what} must be standard base64") from exc
    if len(raw) != _KEY_LEN:
        raise ConfigError(f"{what} must decode to {_KEY_LEN} bytes for {METHOD}")


def xray_inbound(settings: Ss2022Settings, users: list[User]) -> dict[str, Any]:
    clients = []
    for u in users:
        pw = settings.user_passwords.get(u.label)
        if not pw:
            raise ConfigError(f"ss2022 missing password for user {u.label!r}")
        clients.append({"password": pw, "email": u.label})
    return {
        "tag": f"in-ss2022-{settings.port}",
        "listen": "0.0.0.0",  # noqa: S104 - public SS2022 inbound
        "port": settings.port,
        "protocol": "shadowsocks",
        "settings": {
            "method": METHOD,
            "password": settings.server_password,
            "clients": clients,
        },
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
    }


def share_link(settings: Ss2022Settings, host: str, user: User, name: str) -> str:
    """``ss://`` link for a 2022 multi-user client (server:user password)."""
    validate_host(host, "ss2022 host")
    user_pw = settings.user_passwords.get(user.label)
    if not user_pw:
        raise ConfigError(f"ss2022 missing password for user {user.label!r}")
    # Xray/sing-box 2022 multi-user: password = base64server:base64user
    password = f"{settings.server_password}:{user_pw}"
    userinfo = base64.urlsafe_b64encode(f"{METHOD}:{password}".encode()).decode().rstrip("=")
    host_part = host if not (is_ip(host) and ":" in host) else f"[{host}]"
    authority = f"{userinfo}@{host_part}:{settings.port}"
    return f"ss://{authority}#{quote(name, safe='')}"
