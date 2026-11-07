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
from typing import Any, cast

from . import keys
from .hysteria2 import Hy2Settings, share_link
from .models import (
    CRISIS_PORTS,
    RISKY_TARGET_SUFFIXES,
    TUNING_PROFILES,
    ConfigError,
    Endpoint,
    Listener,
    Profile,
    RealityServer,
    ServerSettings,
    User,
    is_ip,
    validate_host,
)
from .shadowsocks import Ss2022Settings
from .warp import WarpSettings

STATE_VERSION = 1
_STATS_UNSET = object()


def _migrate_xhttp_path(path: str, profile: Profile) -> str:
    """Old installs used path ``/``, which stalls REALITY+XHTTP against a cover site root."""
    if path == "/" and profile is Profile.REALITY_XHTTP:
        return "/shahrah"
    return path


def _listener_from_state(data: dict) -> Listener:
    profile = Profile(data["profile"])
    if profile is Profile.PLAIN_WS:
        return Listener(
            data["port"],
            profile,
            data.get("xhttp_path", "/shahrah"),
            data.get("xhttp_mode", "stream-one"),
            data.get("cdn_host", ""),
            data.get("edge_tls", True),
            data.get("edge_port", 0),
            data.get("ws_path", "/shahrah-ws"),
            data.get("ws_host", ""),
        )
    return Listener(
        data["port"],
        profile,
        _migrate_xhttp_path(data["xhttp_path"], profile),
        data["xhttp_mode"],
        data.get("cdn_host", ""),
        data.get("edge_tls", True),
        data.get("edge_port", 0),
        data.get("ws_path", "/shahrah-ws"),
        data.get("ws_host", ""),
    )


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
    xhttp_path: str = "/shahrah"
    xhttp_mode: str = "stream-one"
    allow_non_443: bool = False
    access_log: str | None = None
    tuning_profile: str = "default"  # key of models.TUNING_PROFILES
    stats_api_port: int | None = None  # loopback StatsService; None = disabled
    # Optional WaterWall / domestic entry: REALITY clients dial this instead of public_host.
    # Hy2/SS2022 keep public_host (the exit). CDN/plain-ws keep their own host fields.
    client_host: str | None = None
    users: tuple[User, ...] = field(default_factory=tuple)
    extra_listeners: tuple[Listener, ...] = ()
    hysteria2: Hy2Settings | None = None  # optional QUIC/UDP social path
    warp: WarpSettings | None = None  # optional Cloudflare WARP egress for Google
    ss2022: Ss2022Settings | None = None

    def __post_init__(self) -> None:
        validate_host(self.public_host, "public host")
        if self.client_host:
            validate_host(self.client_host, "client host")
        if self.tuning_profile not in TUNING_PROFILES:
            raise ConfigError(f"unknown tuning profile {self.tuning_profile!r}")
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
        xhttp_path: str = "/shahrah",
        xhttp_mode: str = "stream-one",
        extra_listeners: tuple[Listener, ...] = (),
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
            extra_listeners=extra_listeners,
        )

    def server_settings(self, *, stats_api_port: object = _STATS_UNSET) -> ServerSettings:
        resolved = (
            self.stats_api_port
            if stats_api_port is _STATS_UNSET
            else cast("int | None", stats_api_port)
        )
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
            stats_api_port=resolved,
            access_log=self.access_log,
            extra_listeners=self.extra_listeners,
            tuning=TUNING_PROFILES[self.tuning_profile],
        )

    def with_tuning_profile(self, name: str) -> NodeState:
        if name not in TUNING_PROFILES:
            raise ConfigError(f"unknown tuning profile {name!r}: {sorted(TUNING_PROFILES)}")
        return replace(self, tuning_profile=name)

    def with_access_log(self, path: str | None) -> NodeState:
        """Enable or disable the Xray access log (required for SNI watch)."""
        return replace(self, access_log=path)

    def with_ss2022(self, settings: Ss2022Settings | None) -> NodeState:
        return replace(self, ss2022=settings)

    def with_warp(self, settings: WarpSettings | None) -> NodeState:
        """Attach or clear Cloudflare WARP egress (Google-family / route-all)."""
        return replace(self, warp=settings)

    def with_hysteria2(self, settings: Hy2Settings | None) -> NodeState:
        """Enable (or with ``None`` disable) the Hysteria2 UDP path."""
        return replace(self, hysteria2=settings)

    def ss2022_links(self, user: User, prefix: str = "main") -> list[str]:
        if self.ss2022 is None:
            return []
        from .shadowsocks import share_link as ss_link

        name = f"{prefix}-ss2022-{self.ss2022.port}"
        return [ss_link(self.ss2022, self.public_host, user, name)]

    def hysteria2_links(self, user: User, prefix: str = "main") -> list[str]:
        """``hysteria2://`` links for ``user`` (empty when the path is disabled)."""
        if self.hysteria2 is None:
            return []
        name = f"{prefix}-hy2-{self.hysteria2.port}"
        return [share_link(self.hysteria2, self.public_host, user, name)]

    def with_stats_api(self, port: int | None) -> NodeState:
        """Enable or disable the loopback StatsService used for usage accounting."""
        return replace(self, stats_api_port=port)

    def endpoints(self, prefix: str = "main") -> list[Endpoint]:
        """One client endpoint per listener, named ``<prefix>-<port>``.

        Priority follows the crisis order 443 -> 80 -> 53, so ready-made clients try the most
        mainstream port first and keep the others as fall-overs.
        """
        crisis_rank = {port: rank for rank, port in enumerate(CRISIS_PORTS)}
        out: list[Endpoint] = []
        for listener in self.server_settings().listeners():
            if listener.profile is Profile.CDN_XHTTP:
                out.append(self._cdn_endpoint(prefix, listener, len(CRISIS_PORTS)))
            elif listener.profile is Profile.PLAIN_WS:
                host = listener.ws_host or self.public_host
                out.append(
                    Endpoint(
                        name=f"{prefix}-ws-{listener.port}",
                        host=host,
                        port=listener.port,
                        profile=listener.profile,
                        sni=listener.ws_host or host,
                        tls=False,
                        xhttp_path=listener.ws_path,
                        xhttp_mode="stream-one",
                        priority=crisis_rank.get(listener.port, len(CRISIS_PORTS)),
                    )
                )
            else:
                # Domestic WaterWall entry usually publishes crisis TCP ports (443/80/53).
                # Front those through client_host; any other REALITY port stays on public_host
                # (the entry does not forward arbitrary high ports).
                if self.client_host and listener.port in CRISIS_PORTS:
                    host = self.client_host
                else:
                    host = self.public_host
                out.append(
                    Endpoint(
                        name=f"{prefix}-{listener.port}",
                        host=host,
                        port=listener.port,
                        profile=listener.profile,
                        public_key=self.public_key,
                        short_id=self.short_ids[0],
                        sni=self.target_host,
                        xhttp_path=listener.xhttp_path,
                        xhttp_mode=listener.xhttp_mode,
                        priority=crisis_rank.get(listener.port, len(CRISIS_PORTS)),
                    )
                )
        return out

    @staticmethod
    def _cdn_endpoint(prefix: str, listener: Listener, priority: int) -> Endpoint:
        """Clients reach a CDN listener through the edge (443 with TLS, 80 without)."""
        return Endpoint(
            name=f"{prefix}-cdn-{listener.port}",
            host=listener.cdn_host,
            port=(listener.edge_port if listener.edge_port else (443 if listener.edge_tls else 80)),
            profile=listener.profile,
            sni=listener.cdn_host if listener.edge_tls else "",
            tls=listener.edge_tls,
            xhttp_path=listener.xhttp_path,
            xhttp_mode=listener.xhttp_mode,
            priority=priority,
            # Assumption to confirm in the field tests: a CDN edge stays reachable when
            # direct server IPs do not.
            lockdown_capable=True,
        )

    def endpoint(self, name: str = "main") -> Endpoint:
        """The primary listener's endpoint (kept for single-port callers)."""
        return replace(self.endpoints()[0], name=name)

    def with_listener(self, listener: Listener) -> NodeState:
        return replace(self, extra_listeners=(*self.extra_listeners, listener))

    def without_listener(self, port: int) -> NodeState:
        if port == self.port:
            raise ConfigError("the primary listener cannot be removed")
        remaining = tuple(item for item in self.extra_listeners if item.port != port)
        if len(remaining) == len(self.extra_listeners):
            raise ConfigError(f"no extra listener on port {port}")
        return replace(self, extra_listeners=remaining)

    def with_client_host(self, client_host: str | None) -> NodeState:
        """Front REALITY client links through a domestic WaterWall entry (or clear it)."""
        if client_host:
            validate_host(client_host, "client host")
        return replace(self, client_host=client_host)

    def with_target(self, target_host: str) -> NodeState:
        """Point REALITY at a different TLS 1.3 site (the public SNI clients dial)."""
        validate_host(target_host, "REALITY target host")
        if is_ip(target_host):
            raise ConfigError("REALITY target must be a domain name, not an IP address")
        if target_host.endswith(RISKY_TARGET_SUFFIXES):
            raise ConfigError(
                f"REALITY target {target_host!r} is known to get server IPs blocked; "
                "pick another TLS 1.3 site"
            )
        return replace(self, target_host=target_host)

    def rotate_reality(self, *, new_short_id: bool = True) -> NodeState:
        """Replace the REALITY private key (and usually the short id).

        Existing client links break until they are re-issued. Call ``apply`` and restart Xray
        after saving. Used when a private key may have leaked.
        """
        private, public = keys.generate_keypair()
        short_ids = (keys.generate_short_id(),) if new_short_id else self.short_ids
        return replace(self, private_key=private, public_key=public, short_ids=short_ids)

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
            "client_host": self.client_host,
            "profile": str(self.profile),
            "target_host": self.target_host,
            "target_port": self.target_port,
            "private_key": self.private_key,
            "public_key": self.public_key,
            "short_ids": list(self.short_ids),
            "port": self.port,
            "allow_non_443": self.allow_non_443,
            "access_log": self.access_log,
            "tuning_profile": self.tuning_profile,
            "stats_api_port": self.stats_api_port,
            "xhttp_path": self.xhttp_path,
            "xhttp_mode": self.xhttp_mode,
            "users": [{"uuid": user.uuid, "label": user.label} for user in self.users],
            "listeners": [
                {
                    "port": item.port,
                    "profile": str(item.profile),
                    "xhttp_path": item.xhttp_path,
                    "xhttp_mode": item.xhttp_mode,
                    "cdn_host": item.cdn_host,
                    "edge_tls": item.edge_tls,
                    "edge_port": item.edge_port,
                    "ws_path": item.ws_path,
                    "ws_host": item.ws_host,
                }
                for item in self.extra_listeners
            ],
        }
        if self.hysteria2 is not None:
            data["hysteria2"] = self.hysteria2.to_dict()
        if self.warp is not None:
            data["warp"] = self.warp.to_dict()
        if self.ss2022 is not None:
            data["ss2022"] = self.ss2022.to_dict()
        return json.dumps(data, indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, text: str) -> NodeState:
        try:
            data = json.loads(text)
            if data["version"] != STATE_VERSION:
                raise ConfigError(f"unsupported state version {data['version']!r}")
            return cls(
                public_host=data["public_host"],
                client_host=data.get("client_host"),
                profile=Profile(data["profile"]),
                target_host=data["target_host"],
                target_port=data["target_port"],
                private_key=data["private_key"],
                public_key=data["public_key"],
                short_ids=tuple(data["short_ids"]),
                port=data["port"],
                allow_non_443=data["allow_non_443"],
                access_log=data.get("access_log"),
                tuning_profile=data.get("tuning_profile", "default"),
                stats_api_port=data.get("stats_api_port"),
                xhttp_path=_migrate_xhttp_path(data["xhttp_path"], Profile(data["profile"])),
                xhttp_mode=data["xhttp_mode"],
                users=tuple(User(u["uuid"], u["label"]) for u in data["users"]),
                extra_listeners=tuple(_listener_from_state(i) for i in data.get("listeners", [])),
                hysteria2=Hy2Settings.from_dict(data["hysteria2"])
                if data.get("hysteria2")
                else None,
                warp=WarpSettings.from_dict(data["warp"]) if data.get("warp") else None,
                ss2022=Ss2022Settings.from_dict(data["ss2022"]) if data.get("ss2022") else None,
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
