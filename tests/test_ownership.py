from __future__ import annotations

from pathlib import Path

import pytest

from shahrah.models import ConfigError
from shahrah.ownership import (
    assert_safe_path,
    build_uninstall_plan,
    default_manifest,
    validate_unit_name,
)


def test_refuse_path_outside_ownership() -> None:
    with pytest.raises(ConfigError, match="outside shahrah"):
        assert_safe_path(Path("/etc/ssh/sshd_config"))


def test_refuse_dotdot() -> None:
    with pytest.raises(ConfigError, match="unsafe"):
        assert_safe_path(Path("/etc/shahrah/../ssh"))


def test_validate_template_instance() -> None:
    assert validate_unit_name("shahrah-waterwall@de").startswith("shahrah-waterwall@")


def test_plan_purge_scoped_paths() -> None:
    manifest = default_manifest()
    plan = build_uninstall_plan(manifest, purge_data=True)
    paths = plan["paths"]
    assert "/etc/shahrah" in paths
    assert all("ssh" not in str(p) for p in paths)
