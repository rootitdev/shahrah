"""Least-privilege PasarGuard admin-role presets.

Payloads for ``POST /api/admin-role``. The panel's built-in *owner* role is the root admin;
these two cover everyone else:

* ``sales_manager_role`` - may only create and manage **their own** customers, and only from
  an allow-list of plan templates, within quota/expiry/count caps. No access to hosts, nodes,
  settings or other managers' customers.
* ``brain_role`` - the service identity Shahrah uses. It can list and reorder/disable hosts
  and read nodes, nothing else; if its API key leaks, users and money are out of reach.

Customers are not panel admins: they see what they bought on their subscription page.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .models import ConfigError

_SCOPE_OWN = {"scope": 1}  # PermissionScope.OWN in PasarGuard


def sales_manager_role(
    name: str,
    *,
    allowed_template_ids: Sequence[int],
    max_users: int | None = None,
    data_limit_max_bytes: int | None = None,
    expire_max_seconds: int | None = None,
) -> dict[str, Any]:
    if not name.strip():
        raise ConfigError("role name must not be empty")
    if not allowed_template_ids:
        raise ConfigError("a sales role must be restricted to at least one plan template")
    for label, value in (
        ("max_users", max_users),
        ("data_limit_max_bytes", data_limit_max_bytes),
        ("expire_max_seconds", expire_max_seconds),
    ):
        if value is not None and value <= 0:
            raise ConfigError(f"{label} must be positive")
    return {
        "name": name,
        "permissions": {
            "users": {
                "create": True,
                "read": _SCOPE_OWN,
                "read_simple": _SCOPE_OWN,
                "update": _SCOPE_OWN,
                "delete": _SCOPE_OWN,
                "reset_usage": _SCOPE_OWN,
                "revoke_sub": _SCOPE_OWN,
            },
            "templates": {"read": True, "read_simple": True},
        },
        "limits": {
            "max_users": max_users,
            "data_limit_max": data_limit_max_bytes,
            "expire_max": expire_max_seconds,
        },
        "features": {"can_use_reset_strategy": False, "can_use_next_plan": False},
        "access": {
            "require_template": True,
            "allowed_template_ids": sorted(set(allowed_template_ids)),
        },
    }


def brain_role(name: str = "shahrah-brain") -> dict[str, Any]:
    if not name.strip():
        raise ConfigError("role name must not be empty")
    return {
        "name": name,
        "permissions": {
            "hosts": {"read": True, "update": True},
            "nodes": {"read": True},
        },
    }
