"""Shared fixtures. All hosts use reserved example domains / TEST-NET addresses."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from shahrah.models import Endpoint, Profile, RealityServer, ServerSettings, User

FAKE_KEY = "A" * 43  # shape-valid X25519 key for pure (non-Xray) tests


@pytest.fixture
def reality() -> RealityServer:
    return RealityServer(
        target_host="www.example.com",
        private_key=FAKE_KEY,
        short_ids=("0123456789abcdef", "ab"),
    )


@pytest.fixture
def server(reality: RealityServer) -> ServerSettings:
    return ServerSettings(profile=Profile.REALITY_VISION, reality=reality, stats_api_port=10085)


@pytest.fixture
def users() -> list[User]:
    return [
        User("11111111-1111-4111-8111-111111111111", "u-alpha"),
        User("22222222-2222-4222-8222-222222222222", "u-beta"),
    ]


@pytest.fixture
def endpoint() -> Endpoint:
    return Endpoint(
        name="exit-1 vision",
        host="203.0.113.10",
        port=443,
        profile=Profile.REALITY_VISION,
        public_key=FAKE_KEY,
        short_id="0123456789abcdef",
        sni="www.example.com",
    )


@pytest.fixture(scope="session")
def xray_bin() -> str:
    """Path to a real Xray binary, or skip. Set XRAY_BIN or put `xray` on PATH."""
    path = os.environ.get("XRAY_BIN") or shutil.which("xray")
    if not path or not Path(path).exists():
        pytest.skip("no Xray binary available (set XRAY_BIN)")
    return path


@pytest.fixture(scope="session")
def real_private_key(xray_bin: str) -> str:
    out = subprocess.run([xray_bin, "x25519"], capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        if line.startswith("PrivateKey:"):
            return line.split(":", 1)[1].strip()
    raise AssertionError(f"could not parse `xray x25519` output: {out!r}")
