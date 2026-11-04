"""Bridge between the path-health Oracle and a PasarGuard management panel.

PasarGuard stays the system of record for admins, sales roles, plans, quotas and
subscriptions. Shahrah only *steers* it: it reorders and disables/enables panel **hosts**
(the entries clients receive in their subscription) according to measured tunnel health, so
ready-made clients automatically stop seeing dead paths.

The integration talks to the public REST API with a least-privilege API key and does not
import any PasarGuard code (it is AGPL-3.0; this project stays independent of it).

Safety rules, all enforced in :func:`plan_sync` and covered by tests:

* If no path is healthy, change **nothing**. A blind prober must never be able to empty
  everyone's subscription; failing open is safer than failing closed.
* Only hosts explicitly mapped to a Shahrah path are touched.
* Changes are minimal and idempotent: nothing is sent when the panel already matches.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .models import ConfigError

Json = Any
# (method, url, headers, body) -> (status, parsed JSON or None)
Transport = Callable[[str, str, Mapping[str, str], bytes | None], tuple[int, Json]]

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class PanelError(RuntimeError):
    """The panel rejected a request or could not be reached."""


def _make_transport(*, insecure_tls: bool = False) -> Transport:
    """Build a urllib transport. ``insecure_tls`` is for lab self-signed panel certs only."""

    def transport(
        method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> tuple[int, Json]:
        request = urllib.request.Request(url, data=body, method=method, headers=dict(headers))  # noqa: S310
        handlers: list[urllib.request.BaseHandler] = []
        if urlsplit(url).hostname in _LOOPBACK_HOSTS:
            handlers.append(urllib.request.ProxyHandler({}))
        if insecure_tls:
            ctx = ssl._create_unverified_context()  # noqa: S323 - explicit lab opt-in
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        opener = urllib.request.build_opener(*handlers)
        try:
            with opener.open(request, timeout=15) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw) if raw else None
            except ValueError:
                return exc.code, None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            hint = ""
            name = type(exc).__name__
            if name == "RemoteDisconnected" and urlsplit(url).scheme == "http":
                hint = (
                    " (panel may require https:// — set SHAHRAH_PANEL_URL "
                    "and SHAHRAH_PANEL_INSECURE_TLS=1 for lab)"
                )
            raise PanelError(f"panel unreachable: {name}{hint}") from exc

    return transport


def _default_transport(
    method: str, url: str, headers: Mapping[str, str], body: bytes | None
) -> tuple[int, Json]:
    return _make_transport(insecure_tls=False)(method, url, headers, body)


def probe_user_payload(username: str, vless_uuid: str, group_ids: Sequence[int]) -> dict[str, Any]:
    """``POST /api/user`` body for the unlimited prober account."""
    return {
        "username": username,
        "proxy_settings": {"vless": {"id": vless_uuid}},
        "group_ids": sorted(set(group_ids)),
        "data_limit": 0,
        "expire": 0,
        "note": "shahrah prober - do not delete",
    }


def client_template_payload(name: str, content: str, *, make_default: bool) -> dict[str, Any]:
    """``POST /api/client_template`` body for an Xray JSON subscription template."""
    json.loads(content)  # refuse to upload something the panel would choke on later
    return {
        "name": name,
        "template_type": "xray_subscription",
        "content": content,
        "is_default": make_default,
    }


class PanelClient:
    """Minimal PasarGuard REST client authenticated with an ``X-Api-Key``."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        allow_insecure_http: bool = False,
        insecure_tls: bool = False,
        transport: Transport | None = None,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ConfigError("panel url must look like https://panel.example.org")
        local = parts.hostname in _LOOPBACK_HOSTS
        if parts.scheme == "http" and not (local or allow_insecure_http):
            raise ConfigError("refusing to send the API key over plain http (use https)")
        if insecure_tls and not local:
            raise ConfigError("insecure_tls is only allowed for loopback panel URLs")
        if not api_key.strip():
            raise ConfigError("panel api key must not be empty")
        self._base = base_url.rstrip("/")
        self._key = api_key.strip()
        self._transport = transport or _make_transport(insecure_tls=insecure_tls)

    def __repr__(self) -> str:  # never leak the key through logs or tracebacks
        return f"PanelClient(base_url={self._base!r}, api_key=***)"

    def _request(self, method: str, path: str, payload: Json = None) -> Json:
        headers = {"X-Api-Key": self._key, "Accept": "application/json"}
        body: bytes | None = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        status, data = self._transport(method, f"{self._base}{path}", headers, body)
        if status >= 400:
            detail = data.get("detail") if isinstance(data, dict) else None
            raise PanelError(f"{method} {path} failed with HTTP {status}: {detail or 'no detail'}")
        return data

    def _get_optional(self, path: str) -> Json:
        """GET that returns ``None`` on 404 instead of raising."""
        headers = {"X-Api-Key": self._key, "Accept": "application/json"}
        status, data = self._transport("GET", f"{self._base}{path}", headers, None)
        if status == 404:
            return None
        if status >= 400:
            detail = data.get("detail") if isinstance(data, dict) else None
            raise PanelError(f"GET {path} failed with HTTP {status}: {detail or 'no detail'}")
        return data

    def ensure_role(self, payload: Mapping[str, Any]) -> bool:
        """Create an admin role unless one with that name exists. Returns True if created.

        An existing role is never modified: silently changing permissions on a role that
        real people already use would be a dangerous surprise.
        """
        data = self._request("GET", "/api/admin-roles")
        roles = data.get("roles", []) if isinstance(data, dict) else []
        if any(role.get("name") == payload["name"] for role in roles):
            return False
        self._request("POST", "/api/admin-role", dict(payload))
        return True

    def list_user_templates(self) -> list[dict[str, Any]]:
        """Return plan/user templates used to constrain sales roles."""
        data = self._request("GET", "/api/user_templates")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("templates") or data.get("user_templates") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        raise PanelError("unexpected /api/user_templates response")

    def ensure_client_template(
        self, name: str, content: str, *, make_default: bool = False
    ) -> bool:
        """Upload an Xray subscription template unless one with that name exists.

        It is not made the default unless asked: the default applies to every user's config, so
        switching it is an explicit decision. An existing template is never overwritten; use
        :meth:`upsert_client_template` when the operator deliberately wants a refresh.
        """
        data = self._request("GET", "/api/client_templates")
        templates = data.get("templates", []) if isinstance(data, dict) else []
        if any(t.get("name") == name for t in templates):
            return False
        self._request(
            "POST",
            "/api/client_template",
            client_template_payload(name, content, make_default=make_default),
        )
        return True

    def upsert_client_template(self, name: str, content: str, *, make_default: bool = False) -> str:
        """Create or replace a named Xray subscription template.

        Returns ``\"created\"`` or ``\"updated\"``. Replacing content is intentional (leak rules
        evolve); making it the panel default still requires ``make_default=True``.
        """
        data = self._request("GET", "/api/client_templates")
        templates = data.get("templates", []) if isinstance(data, dict) else []
        payload = client_template_payload(name, content, make_default=make_default)
        for template in templates:
            if template.get("name") != name:
                continue
            template_id = template.get("id")
            if template_id is None:
                raise PanelError(f"client template {name!r} has no id")
            self._request("PUT", f"/api/client_template/{template_id}", payload)
            return "updated"
        self._request("POST", "/api/client_template", payload)
        return "created"

    def get_user(self, username: str) -> dict[str, Any]:
        data = self._request("GET", f"/api/user/{username}")
        if not isinstance(data, dict):
            raise PanelError("unexpected user payload")
        return data

    def put_user(self, username: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        data = self._request("PUT", f"/api/user/{username}", dict(payload))
        if not isinstance(data, dict):
            raise PanelError("unexpected user update payload")
        return data

    def ensure_probe_user(self, username: str, vless_uuid: str, group_ids: Sequence[int]) -> bool:
        """Create the unlimited account the prober connects with. Returns True if created.

        The uuid is chosen by Shahrah, so the brain config is static and never has to read
        credentials back from the panel.
        """
        if not group_ids:
            raise ConfigError("the probe user needs at least one group (inbound access)")
        existing = self._get_optional(f"/api/user/{username}")
        if existing is not None:
            current = (existing.get("proxy_settings") or {}).get("vless", {}).get("id")
            if str(current).lower() != vless_uuid.lower():
                raise ConfigError(
                    f"panel user {username!r} already exists with a different vless id; "
                    "use that id or delete the user first"
                )
            return False
        self._request("POST", "/api/user", probe_user_payload(username, vless_uuid, group_ids))
        return True

    def list_cores(self) -> list[dict[str, Any]]:
        data = self._request("GET", "/api/cores")
        cores = data.get("cores", []) if isinstance(data, dict) else []
        if not isinstance(cores, list):
            raise PanelError("unexpected /api/cores response")
        return cores

    def ensure_core(self, payload: Mapping[str, Any]) -> bool:
        """Create a core config unless one with that name exists. Returns True if created.

        An existing core is never modified: replacing a running core would restart Xray for
        every connected user. Use :meth:`update_core` when the operator explicitly wants that.
        """
        if any(core.get("name") == payload["name"] for core in self.list_cores()):
            return False
        self._request("POST", "/api/core", dict(payload))
        return True

    def update_core(self, payload: Mapping[str, Any], *, restart_nodes: bool = False) -> None:
        """Replace an existing core's config by name (PasarGuard ``PUT /api/core/{id}``).

        ``restart_nodes`` is a query flag on the panel API. Default false keeps
        Shahrah-managed independent exits from being restarted by the panel.
        """
        name = payload.get("name")
        match = next((core for core in self.list_cores() if core.get("name") == name), None)
        if match is None or "id" not in match:
            raise PanelError(f"no panel core named {name!r}")
        flag = "true" if restart_nodes else "false"
        self._request(
            "PUT",
            f"/api/core/{match['id']}?restart_nodes={flag}",
            dict(payload),
        )

    def ensure_host(self, payload: Mapping[str, Any]) -> bool:
        """Create a host unless one with that remark exists. Returns True if created."""
        if any(host.get("remark") == payload["remark"] for host in self.list_hosts()):
            return False
        self._request("POST", "/api/host/", dict(payload))
        return True

    def list_hosts(self) -> list[dict[str, Any]]:
        data = self._request("GET", "/api/hosts")
        if not isinstance(data, list):
            raise PanelError("unexpected /api/hosts response")
        return data

    def get_host(self, host_id: int) -> dict[str, Any]:
        data = self._request("GET", f"/api/host/{host_id}")
        if not isinstance(data, dict):
            raise PanelError("unexpected host response")
        return data

    def set_hosts_disabled(self, ids: Sequence[int], *, disabled: bool) -> None:
        if not ids:
            return
        action = "disable" if disabled else "enable"
        self._request("POST", f"/api/hosts/bulk/{action}", {"ids": sorted(ids)})

    def set_host_priority(self, host_id: int, priority: int) -> None:
        """Read-modify-write: the panel's PUT requires the full host object."""
        host = self.get_host(host_id)
        host["priority"] = priority
        self._request("PUT", f"/api/host/{host_id}", host)


@dataclass(frozen=True, slots=True)
class SyncPlan:
    enable: tuple[int, ...] = ()
    disable: tuple[int, ...] = ()
    priorities: Mapping[int, int] = field(default_factory=dict)
    skipped_reason: str | None = None

    @property
    def empty(self) -> bool:
        return not (self.enable or self.disable or self.priorities)


def plan_sync(
    hosts: Sequence[Mapping[str, Any]],
    ranking: Sequence[str],
    path_to_remark: Mapping[str, str],
) -> SyncPlan:
    """Decide the minimal panel changes that make hosts mirror the Oracle ranking.

    ``ranking`` lists healthy path names best-first; mapped paths absent from it are
    unhealthy. ``path_to_remark`` maps a Shahrah path name to the panel host remark.
    """
    if not ranking:
        return SyncPlan(skipped_reason="no healthy path: leaving the panel untouched")

    by_remark: dict[str, Mapping[str, Any]] = {}
    for host in hosts:
        remark = host.get("remark")
        if remark in by_remark:
            raise ConfigError(f"duplicate panel host remark {remark!r}; remarks must be unique")
        by_remark[remark] = host

    missing = [r for r in path_to_remark.values() if r not in by_remark]
    if missing:
        raise ConfigError(f"panel has no host with remark(s): {sorted(missing)}")

    enable: list[int] = []
    disable: list[int] = []
    priorities: dict[int, int] = {}
    healthy = set(ranking)
    for path, remark in path_to_remark.items():
        host = by_remark[remark]
        host_id = host["id"]
        if path in healthy:
            if host.get("is_disabled"):
                enable.append(host_id)
            wanted = ranking.index(path)
            if host.get("priority") != wanted:
                priorities[host_id] = wanted
        elif not host.get("is_disabled"):
            disable.append(host_id)
    return SyncPlan(tuple(sorted(enable)), tuple(sorted(disable)), priorities)


def apply_plan(client: PanelClient, plan: SyncPlan) -> None:
    """Execute a plan. Enabling runs first so subscribers never see zero hosts mid-change."""
    client.set_hosts_disabled(plan.enable, disabled=False)
    for host_id, priority in sorted(plan.priorities.items()):
        client.set_host_priority(host_id, priority)
    client.set_hosts_disabled(plan.disable, disabled=True)


def sync(
    client: PanelClient, ranking: Sequence[str], path_to_remark: Mapping[str, str]
) -> SyncPlan:
    plan = plan_sync(client.list_hosts(), ranking, path_to_remark)
    apply_plan(client, plan)
    return plan
