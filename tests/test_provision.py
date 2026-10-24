from __future__ import annotations

import json
import os
import subprocess
import sys
import types
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from shahrah.cli import main
from shahrah.models import Listener, Profile
from shahrah.panel import PanelClient, PanelError
from shahrah.provision import core_config, core_payload, host_plans, remarks
from shahrah.state import NodeState

PATH = "/s3cret-path-123"


@pytest.fixture
def state() -> NodeState:
    return NodeState.create(
        public_host="203.0.113.10",
        target_host="www.example.com",
        allow_non_443=True,
        extra_listeners=(
            Listener(80, Profile.REALITY_XHTTP),
            Listener(
                8080,
                Profile.CDN_XHTTP,
                xhttp_path=PATH,
                xhttp_mode="packet-up",
                cdn_host="cdn.example.com",
            ),
            Listener(
                8880,
                Profile.CDN_XHTTP,
                xhttp_path=PATH + "x",
                xhttp_mode="auto",
                cdn_host="cdn.example.com",
                edge_tls=False,
            ),
        ),
    )


# --- pure planning -----------------------------------------------------------------------


def test_core_config_has_clients_left_for_the_panel_and_no_local_stats_api(
    state: NodeState,
) -> None:
    config = core_config(state)
    assert [i["tag"] for i in config["inbounds"]] == ["in-main", "in-80", "in-8080", "in-8880"]
    assert all(i["settings"]["clients"] == [] for i in config["inbounds"])
    assert "api" not in config


def test_every_host_points_at_an_existing_inbound_tag(state: NodeState) -> None:
    tags = {i["tag"] for i in core_config(state)["inbounds"]}
    plans = host_plans(state)
    assert {p.payload["inbound_tag"] for p in plans} == tags
    assert len({p.remark for p in plans}) == len(plans)
    assert remarks(plans) == {p.endpoint: p.remark for p in plans}


def test_reality_hosts_keep_the_inbound_security(state: NodeState) -> None:
    by = {p.endpoint: p.payload for p in host_plans(state)}
    main_host, xhttp_host = by["main-443"], by["main-80"]
    assert main_host["security"] == "inbound_default" and main_host["sni"] == ["www.example.com"]
    assert main_host["address"] == ["203.0.113.10"] and main_host["port"] == 443
    assert xhttp_host["transport_settings"] == {"xhttp_settings": {"mode": "stream-one"}}


def test_cdn_hosts_override_security_and_target_the_edge(state: NodeState) -> None:
    by = {p.endpoint: p.payload for p in host_plans(state)}
    tls_edge, plain_edge = by["main-cdn-8080"], by["main-cdn-8880"]
    assert tls_edge["address"] == ["cdn.example.com"] and tls_edge["port"] == 443
    assert tls_edge["security"] == "tls" and tls_edge["sni"] == ["cdn.example.com"]
    assert tls_edge["path"] == PATH and tls_edge["host"] == ["cdn.example.com"]
    assert plain_edge["security"] == "none" and plain_edge["port"] == 80
    assert "sni" not in plain_edge


def test_priorities_keep_the_crisis_order(state: NodeState) -> None:
    by = {p.endpoint: p.payload["priority"] for p in host_plans(state)}
    assert by["main-443"] < by["main-80"] < by["main-cdn-8080"]


def test_payloads_contain_no_private_material_except_the_core_key(state: NodeState) -> None:
    text = json.dumps([p.payload for p in host_plans(state)])
    assert state.private_key not in text
    assert state.private_key in json.dumps(core_payload("n", state))  # the panel must hold it


# --- applying to a panel -----------------------------------------------------------------


class FakePanel:
    def __init__(self) -> None:
        self.cores: list[dict[str, Any]] = []
        self.hosts: list[dict[str, Any]] = []
        self.requests: list[tuple[str, str]] = []

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> tuple[int, Any]:
        path = url.split("//", 1)[1].split("/", 1)[1]
        self.requests.append((method, "/" + path))
        assert headers["X-Api-Key"] == "k"
        payload = json.loads(body) if body else None
        if (method, path) == ("GET", "api/cores"):
            return 200, {"count": len(self.cores), "cores": self.cores}
        if (method, path) == ("POST", "api/core"):
            self.cores.append(payload)
            return 201, payload
        if (method, path) == ("GET", "api/hosts"):
            return 200, self.hosts
        if (method, path) == ("POST", "api/host/"):
            self.hosts.append({**payload, "id": len(self.hosts) + 1})
            return 201, payload
        return 404, {"detail": "nope"}


def test_provision_is_idempotent_and_never_overwrites(state: NodeState) -> None:
    fake = FakePanel()
    client = PanelClient("https://panel.example.org", "k", transport=fake)
    payload = core_payload("shahrah", state)
    assert client.ensure_core(payload) is True
    assert client.ensure_core({**payload, "config": {"changed": True}}) is False
    assert fake.cores[0]["config"] == payload["config"]  # an existing core is left alone
    plans = host_plans(state)
    assert [client.ensure_host(p.payload) for p in plans] == [True] * len(plans)
    assert [client.ensure_host(p.payload) for p in plans] == [False] * len(plans)
    assert len(fake.hosts) == len(plans)


def test_panel_errors_surface(state: NodeState) -> None:
    def failing(*_: object) -> tuple[int, Any]:
        return 403, {"detail": "forbidden"}

    client = PanelClient("https://panel.example.org", "k", transport=failing)
    with pytest.raises(PanelError, match="403"):
        client.ensure_core(core_payload("x", state))


# --- CLI ---------------------------------------------------------------------------------


def test_cli_dry_run_needs_no_panel_and_prints_brain_remarks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    state_path = tmp_path / "state.json"
    assert (
        main(
            [
                "--state",
                str(state_path),
                "init",
                "--host",
                "203.0.113.10",
                "--target",
                "www.example.com",
                "--extra-listener",
                "80:reality-xhttp",
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert main(["--state", str(state_path), "panel", "provision", "--dry-run"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["core"]["state"] == "planned"
    assert out["brain_remarks"] == {"main-443": "main-443", "main-80": "main-80"}


# --- real tools --------------------------------------------------------------------------


def test_real_xray_accepts_the_panel_core_config(
    xray_bin: str, real_keypair: tuple[str, str], state: NodeState, tmp_path: Path
) -> None:
    private, public = real_keypair
    real = replace(state, private_key=private, public_key=public)
    path = tmp_path / "core.json"
    path.write_text(json.dumps(core_config(real)), encoding="utf-8")
    result = subprocess.run(
        [xray_bin, "run", "-test", "-c", str(path)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _load_panel_models() -> types.ModuleType:
    src = Path(os.environ["PASARGUARD_SRC"])
    for name, sub in (("app", "app"), ("app.models", "app/models")):
        module = types.ModuleType(name)
        module.__path__ = [str(src / sub)]
        sys.modules[name] = module
    sys.path.insert(0, str(src))
    from app.models import core, host  # type: ignore[import-not-found]

    return types.SimpleNamespace(CreateHost=host.CreateHost, CoreCreate=core.CoreCreate)  # type: ignore[return-value]


@pytest.mark.skipif(
    "PASARGUARD_SRC" not in os.environ,
    reason="set PASARGUARD_SRC to a PasarGuard checkout (with its deps) to check compatibility",
)
def test_payloads_are_accepted_by_the_real_panel_models(state: NodeState) -> None:
    models = _load_panel_models()
    for plan in host_plans(state):
        models.CreateHost.model_validate(json.loads(json.dumps(plan.payload)))  # type: ignore[attr-defined]
    models.CoreCreate.model_validate(  # type: ignore[attr-defined]
        json.loads(json.dumps(core_payload("shahrah", state)))
    )
    bad = dict(host_plans(state)[0].payload, security="tsl")
    with pytest.raises(ValueError, match="security"):
        models.CreateHost.model_validate(bad)  # type: ignore[attr-defined]
