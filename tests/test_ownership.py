from __future__ import annotations

from pathlib import Path

import pytest

from shahrah.models import ConfigError
from shahrah.ownership import assert_safe_path, default_manifest, plan_removal


def test_refuse_path_outside_ownership() -> None:
    with pytest.raises(ConfigError, match="outside shahrah"):
        assert_safe_path(Path("/etc/ssh/sshd_config"))


def test_refuse_dotdot() -> None:
    with pytest.raises(ConfigError, match="unsafe"):
        assert_safe_path(Path("/etc/shahrah/../ssh"))


def test_plan_purge_only_owned_paths() -> None:
    manifest = default_manifest()
    _, paths = plan_removal(manifest, purge_data=True)
    assert "/etc/shahrah" in paths
    assert all("ssh" not in p for p in paths)
