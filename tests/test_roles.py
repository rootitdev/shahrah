from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path

import pytest

from shahrah.models import ConfigError
from shahrah.roles import brain_role, sales_manager_role


def test_sales_role_is_scoped_to_own_customers_and_templates() -> None:
    role = sales_manager_role("sales", allowed_template_ids=[3, 1, 3], max_users=20)
    users = role["permissions"]["users"]
    assert users["read"] == {"scope": 1}
    assert users["update"] == {"scope": 1}
    assert users["delete"] == {"scope": 1}
    assert "set_owner" not in users  # a manager must not hand customers to someone else
    assert role["access"] == {"require_template": True, "allowed_template_ids": [1, 3]}
    assert role["limits"]["max_users"] == 20
    assert set(role["permissions"]) == {"users", "templates"}  # no hosts/nodes/settings


def test_sales_role_requires_a_template_allow_list_and_sane_caps() -> None:
    with pytest.raises(ConfigError, match="at least one plan template"):
        sales_manager_role("sales", allowed_template_ids=[])
    with pytest.raises(ConfigError, match="positive"):
        sales_manager_role("sales", allowed_template_ids=[1], max_users=0)
    with pytest.raises(ConfigError, match="name"):
        sales_manager_role(" ", allowed_template_ids=[1])


def test_brain_role_can_only_steer_hosts_and_read_nodes() -> None:
    role = brain_role()
    assert role["permissions"] == {
        "hosts": {"read": True, "update": True},
        "nodes": {"read": True},
    }
    assert "create" not in role["permissions"]["hosts"]  # cannot add hosts, only steer them


def _load_real_model() -> type:
    """Load PasarGuard's real AdminRoleCreate without booting the whole panel."""
    src = Path(os.environ["PASARGUARD_SRC"])
    for name, sub in (("app", "app"), ("app.models", "app/models")):
        module = types.ModuleType(name)
        module.__path__ = [str(src / sub)]
        sys.modules[name] = module
    sys.path.insert(0, str(src))
    from app.models.admin_role import AdminRoleCreate

    return AdminRoleCreate


@pytest.mark.skipif(
    "PASARGUARD_SRC" not in os.environ,
    reason="set PASARGUARD_SRC to a PasarGuard checkout (with its deps) to check compatibility",
)
def test_presets_are_accepted_by_the_real_panel_models() -> None:
    model = _load_real_model()
    payloads = [sales_manager_role("sales", allowed_template_ids=[1, 2], max_users=5), brain_role()]
    for payload in payloads:
        model.model_validate(json.loads(json.dumps(payload)))  # type: ignore[attr-defined]
    typo = brain_role()
    typo["permissions"]["hosts"]["updat"] = True
    with pytest.raises(ValueError, match="updat"):
        model.model_validate(typo)  # type: ignore[attr-defined]
