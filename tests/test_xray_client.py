from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from shahrah.models import Endpoint, Profile, User
from shahrah.xray_client import render_probe_config
from shahrah.xray_config import dumps


def test_one_socks_inbound_and_outbound_per_endpoint(endpoint: Endpoint, users: list[User]) -> None:
    second = replace(endpoint, name="exit-2", profile=Profile.REALITY_XHTTP, xhttp_path="/p")
    config = render_probe_config([endpoint, second], users[0], [20001, 20002])
    assert [i["port"] for i in config["inbounds"]] == [20001, 20002]
    assert all(i["listen"] == "127.0.0.1" for i in config["inbounds"])  # never exposed
    vision, xhttp = (o["streamSettings"] for o in config["outbounds"])
    assert vision["network"] == "raw"
    assert xhttp["network"] == "xhttp"
    assert xhttp["xhttpSettings"] == {"path": "/p", "mode": "stream-one"}
    rules = config["routing"]["rules"]
    assert [(r["inboundTag"], r["outboundTag"]) for r in rules] == [
        (["probe-in-0"], "probe-out-0"),
        (["probe-in-1"], "probe-out-1"),
    ]


def test_vision_outbound_carries_flow_and_xhttp_does_not(
    endpoint: Endpoint, users: list[User]
) -> None:
    xhttp = replace(endpoint, name="x", profile=Profile.REALITY_XHTTP)
    config = render_probe_config([endpoint, xhttp], users[0], [20001, 20002])
    flows = [o["settings"]["vnext"][0]["users"][0].get("flow") for o in config["outbounds"]]
    assert flows == ["xtls-rprx-vision", None]


@pytest.mark.parametrize(
    ("endpoints", "ports", "message"),
    [
        (1, [1, 2], "one local port"),
        (2, [5, 5], "unique"),
        (0, [], "at least one"),
    ],
)
def test_invalid_inputs(
    endpoint: Endpoint, users: list[User], endpoints: int, ports: list[int], message: str
) -> None:
    eps = [replace(endpoint, name=f"e{i}") for i in range(endpoints)]
    with pytest.raises(ValueError, match=message):
        render_probe_config(eps, users[0], ports)


@pytest.mark.parametrize("profile", list(Profile))
def test_real_xray_accepts_probe_config(
    profile: Profile,
    endpoint: Endpoint,
    users: list[User],
    xray_bin: str,
    real_keypair: tuple[str, str],
    tmp_path: Path,
) -> None:
    ep = replace(endpoint, profile=profile, public_key=real_keypair[1])
    path = tmp_path / "client.json"
    path.write_text(dumps(render_probe_config([ep], users[0], [20001])), encoding="utf-8")
    result = subprocess.run(
        [xray_bin, "run", "-test", "-c", str(path)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Configuration OK" in result.stdout + result.stderr
