"""Multi-exit PasarGuard fleet planning (add-only hosts/cores from node state files)."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import ConfigError
from .panel import PanelClient, PanelError
from .provision import core_payload, host_plans
from .state import load_state


@dataclass(frozen=True, slots=True)
class FleetMember:
    slug: str
    state_path: Path
    core_name: str
    host_prefix: str
    client_host: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FleetMember:
        slug = str(data.get("slug") or data.get("name") or "").strip()
        if not slug:
            raise ConfigError("fleet member needs slug or name")
        path_raw = data.get("state_path") or data.get("state")
        if not path_raw:
            raise ConfigError(f"fleet member {slug!r} needs state_path")
        core = str(data.get("core_name") or f"shahrah-{slug}")
        prefix = str(data.get("host_prefix") or slug)
        ch = data.get("client_host")
        client_host = str(ch).strip() if ch else None
        return cls(slug, Path(path_raw), core, prefix, client_host)


@dataclass(frozen=True, slots=True)
class FleetSpec:
    members: tuple[FleetMember, ...]
    note: str = ""

    @classmethod
    def from_json(cls, text: str) -> FleetSpec:
        data = json.loads(text)
        raw = data.get("exits") or data.get("members") or []
        if not isinstance(raw, list) or not raw:
            raise ConfigError("fleet spec needs a non-empty exits[] array")
        return cls(tuple(FleetMember.from_dict(item) for item in raw), str(data.get("note", "")))

    @classmethod
    def from_path(cls, path: Path) -> FleetSpec:
        return cls.from_json(path.read_text(encoding="utf-8"))


def _member_state(member: FleetMember):
    state = load_state(member.state_path)
    if member.client_host:
        state = state.with_client_host(member.client_host)
    return state


def plan_member(member: FleetMember) -> dict[str, Any]:
    state = _member_state(member)
    plans = host_plans(state, prefix=member.host_prefix)
    return {
        "slug": member.slug,
        "state_path": str(member.state_path),
        "core_name": member.core_name,
        "client_host": member.client_host,
        "core": core_payload(member.core_name, state),
        "hosts": [plan.payload for plan in plans],
        "brain_remarks": {plan.endpoint: plan.remark for plan in plans},
    }


def plan_fleet(client: PanelClient, spec: FleetSpec) -> dict[str, Any]:
    existing_cores = {str(c.get("name")) for c in client.list_cores()}
    existing_remarks = {str(h.get("remark")) for h in client.list_hosts()}
    problems: list[str] = []
    planned: list[dict[str, Any]] = []
    seen_cores: set[str] = set()
    seen_remarks: set[str] = set()
    all_brain: dict[str, str] = {}

    for member in spec.members:
        if not member.state_path.is_file():
            problems.append(f"{member.slug}: missing state file {member.state_path}")
            continue
        try:
            block = plan_member(member)
        except (ConfigError, OSError, json.JSONDecodeError, PanelError) as exc:
            problems.append(f"{member.slug}: {exc}")
            continue
        planned.append(block)
        cn = block["core_name"]
        if cn in existing_cores:
            problems.append(f"panel already has core {cn!r}")
        if cn in seen_cores:
            problems.append(f"duplicate core_name in fleet spec: {cn!r}")
        seen_cores.add(cn)
        for host in block["hosts"]:
            remark = str(host.get("remark"))
            if remark in existing_remarks:
                problems.append(f"panel already has host remark {remark!r}")
            if remark in seen_remarks:
                problems.append(f"duplicate host remark in fleet spec: {remark!r}")
            seen_remarks.add(remark)
        for ep, rm in block["brain_remarks"].items():
            all_brain[f"{member.slug}:{ep}"] = rm

    return {
        "note": spec.note,
        "planned": planned,
        "problems": problems,
        "brain_remarks_merged": all_brain,
        "ok": not problems,
    }


def apply_fleet(
    client: PanelClient,
    spec: FleetSpec,
    *,
    update_core: bool = False,
    restart_nodes: bool = False,
) -> dict[str, Any]:
    plan = plan_fleet(client, spec)
    if not plan["ok"]:
        raise ConfigError("fleet plan has blockers: " + "; ".join(plan["problems"]))
    results: list[dict[str, Any]] = []
    for member in spec.members:
        block = plan_member(member)
        payload = block["core"]
        created = client.ensure_core(payload)
        core_state = "created" if created else "exists"
        if not created and update_core:
            client.update_core(payload, restart_nodes=restart_nodes)
            core_state = "updated"
        hosts_out: dict[str, str] = {}
        for host in block["hosts"]:
            remark = str(host["remark"])
            hosts_out[remark] = "created" if client.ensure_host(host) else "exists"
        results.append(
            {
                "slug": member.slug,
                "core_name": member.core_name,
                "core_state": core_state,
                "hosts": hosts_out,
                "brain_remarks": block["brain_remarks"],
            }
        )
    return {"applied": results, "brain_remarks_merged": plan["brain_remarks_merged"]}


def snapshot_panel(client: PanelClient, out_dir: Path) -> Path:
    out = out_dir / time.strftime("%Y%m%dT%H%M%SZ")
    out.mkdir(parents=True, exist_ok=True)
    for name, fetch in (
        ("cores", client.list_cores),
        ("hosts", client.list_hosts),
    ):
        (out / f"{name}.json").write_text(
            json.dumps(fetch(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    return out