"""Persistent node state: one JSON file holding REALITY keys, users and public address.

The file contains the REALITY private key, so it is written atomically with owner-only
permissions. Everything is re-validated through the model classes on load, so a hand-edited
or corrupted file fails loudly instead of producing a broken Xray config.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from . import keys
from .models import (
    ConfigError,
    Endpoint,
    Profile,
    RealityServer,
    ServerSettings,
    User,
    validate_host,
)

STATE_VERSION = 1


@dataclass(frozen=True, slots=True)
class NodeState:
    """Everything needed to render the server config and the client-facing endpoint."""

    public_host: str
    profile: Profile
    target_host: str
    private_key: str
    public_key: str
    short_ids: tuple[str, ...]
    port: int = 443
    target_port: int = 443
    xhttp_path: str = "/"
    xhttp_mode: str = "stream-one"
    allow_non_443: bool = False
    users: tuple[User, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        validate_host(self.public_host, "public host")
        if keys.public_from_private(self.private_key) != self.public_key:
            raise ConfigError("REALITY public key does not match the private key")
        labels = [user.label for user in self.users]
        if len(set(labels)) != len(labels):
            raise ConfigError("user labels must be unique")
        self.server_settings()  # validates every remaining field via the model classes

    @classmethod
    def create(
        cls,
        *,
        public_host: str,
        target_host: str,
        profile: Profile = Profile.REALITY_VISION,
        port: int = 443,
        allow_non_443: bool = False,
        xhttp_path: str = "/",
        xhttp_mode: str = "stream-one",
    ) -> NodeState:
        private, public = keys.generate_keypair()
        return cls(
            public_host=public_host,
            profile=profile,
            target_host=target_host,
            private_key=private,
            public_key=public,
            short_ids=(keys.generate_short_id(),),
            port=port,
            allow_non_443=allow_non_443,
            xhttp_path=xhttp_path,
            xhttp_mode=xhttp_mode,
        )

    def server_settings(self, *, stats_api_port: int | None = None) -> ServerSettings:
        return ServerSettings(
            profile=self.profile,
            reality=RealityServer(
                target_host=self.target_host,
                private_key=self.private_key,
                short_ids=self.short_ids,
                target_port=self.target_port,
            ),
            port=self.port,
            xhttp_path=self.xhttp_path,
            xhttp_mode=self.xhttp_mode,
            allow_non_443=self.allow_non_443,
            stats_api_port=stats_api_port,
        )

    def endpoint(self, name: str = "main") -> Endpoint:
        return Endpoint(
            name=name,
            host=self.public_host,
            port=self.port,
            profile=self.profile,
            public_key=self.public_key,
            short_id=self.short_ids[0],
            sni=self.target_host,
            xhttp_path=self.xhttp_path,
            xhttp_mode=self.xhttp_mode,
        )

    def with_user(self, label: str) -> tuple[NodeState, User]:
        if any(user.label == label for user in self.users):
            raise ConfigError(f"user {label!r} already exists")
        user = User.create(label)
        return replace(self, users=(*self.users, user)), user

    def without_user(self, label: str) -> NodeState:
        remaining = tuple(user for user in self.users if user.label != label)
        if len(remaining) == len(self.users):
            raise ConfigError(f"no such user: {label!r}")
        return replace(self, users=remaining)

    def find_user(self, label: str) -> User:
        for user in self.users:
            if user.label == label:
                return user
        raise ConfigError(f"no such user: {label!r}")

    def to_json(self) -> str:
        data: dict[str, Any] = {
            "version": STATE_VERSION,
            "public_host": self.public_host,
            "profile": str(self.profile),
            "target_host": self.target_host,
            "target_port": self.target_port,
            "private_key": self.private_key,
            "public_key": self.public_key,
            "short_ids": list(self.short_ids),
            "port": self.port,
            "allow_non_443": self.allow_non_443,
            "xhttp_path": self.xhttp_path,
            "xhttp_mode": self.xhttp_mode,
            "users": [{"uuid": user.uuid, "label": user.label} for user in self.users],
        }
        return json.dumps(data, indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, text: str) -> NodeState:
        try:
            data = json.loads(text)
            if data["version"] != STATE_VERSION:
                raise ConfigError(f"unsupported state version {data['version']!r}")
            return cls(
                public_host=data["public_host"],
                profile=Profile(data["profile"]),
                target_host=data["target_host"],
                target_port=data["target_port"],
                private_key=data["private_key"],
                public_key=data["public_key"],
                short_ids=tuple(data["short_ids"]),
                port=data["port"],
                allow_non_443=data["allow_non_443"],
                xhttp_path=data["xhttp_path"],
                xhttp_mode=data["xhttp_mode"],
                users=tuple(User(u["uuid"], u["label"]) for u in data["users"]),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            if isinstance(exc, ConfigError):
                raise
            raise ConfigError(f"state file is invalid: {exc}") from exc


def write_private_file(path: Path, text: str) -> None:
    """Atomically write ``text`` to ``path`` readable only by its owner."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        Path(tmp_name).chmod(0o600)
        Path(tmp_name).replace(path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def save_state(path: Path, state: NodeState) -> None:
    write_private_file(path, state.to_json())


def load_state(path: Path) -> NodeState:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(f"state file not found: {path} (run `shahrah init` first)") from exc
    return NodeState.from_json(text)
