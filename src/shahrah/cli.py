"""``shahrah`` command line: initialise a node, manage users, render configs and subscriptions."""

from __future__ import annotations

import argparse
import functools
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from . import client_template, deploy, keys
from .brain import Brain, BrainConfig, PanelSync, describe, run_forever
from .links import build_subscription, vless_link
from .models import ConfigError, Profile, User
from .panel import PanelClient, PanelError, sync
from .prober import ProbeError, ProbeResult, XrayProbeSession
from .roles import brain_role, sales_manager_role
from .state import NodeState, load_state, save_state, write_private_file
from .xray_config import dumps, render_server_config

DEFAULT_STATE = Path(os.environ.get("SHAHRAH_STATE", "/etc/shahrah/state.json"))
DEFAULT_XRAY_CONFIG = Path(os.environ.get("SHAHRAH_XRAY_CONFIG", "/etc/shahrah/xray.json"))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shahrah", description=__doc__)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE, help="node state file")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create a new node (generates REALITY keys)")
    init.add_argument("--host", required=True, help="public domain or IP clients connect to")
    init.add_argument("--target", required=True, help="TLS 1.3 site REALITY imitates")
    init.add_argument(
        "--profile", choices=[p.value for p in Profile], default=Profile.REALITY_VISION
    )
    init.add_argument("--port", type=int, default=443)
    init.add_argument("--allow-non-443", action="store_true")
    init.add_argument("--force", action="store_true", help="overwrite an existing state file")

    apply = sub.add_parser("apply", help="render and validate the Xray server config")
    apply.add_argument("--config-out", type=Path, default=DEFAULT_XRAY_CONFIG)
    apply.add_argument("--xray-bin", default="xray", help="binary used for `run -test`")
    apply.add_argument("--no-validate", action="store_true")
    apply.add_argument("--group", help="group allowed to read the config (the service user)")

    user = sub.add_parser("user", help="manage VPN users")
    user_sub = user.add_subparsers(dest="user_command", required=True)
    add = user_sub.add_parser("add")
    add.add_argument("label")
    remove = user_sub.add_parser("remove")
    remove.add_argument("label")
    user_sub.add_parser("list")

    link = sub.add_parser("link", help="print the vless:// link for a user")
    link.add_argument("label")
    link.add_argument("--name", default="main")

    subscription = sub.add_parser("sub", help="print the base64 subscription body for a user")
    subscription.add_argument("label")
    subscription.add_argument("--name", default="main")

    brain = sub.add_parser("brain", help="probe tunnels and steer the management panel")
    brain.add_argument("--config", type=Path, required=True, help="brain JSON config")
    brain.add_argument("--xray-bin", default="xray")
    brain.add_argument("--panel-url", default=os.environ.get("SHAHRAH_PANEL_URL"))
    brain.add_argument("--once", action="store_true", help="run a single cycle and exit")
    brain.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING"])

    panel = sub.add_parser("panel", help="one-time setup of a PasarGuard panel (owner key)")
    panel.add_argument("--panel-url", default=os.environ.get("SHAHRAH_PANEL_URL"))
    panel_sub = panel.add_subparsers(dest="panel_command", required=True)
    boot = panel_sub.add_parser("bootstrap", help="create the brain role and the probe user")
    boot.add_argument("--probe-group-id", type=int, nargs="+", required=True)
    boot.add_argument("--probe-username", default="shahrah_probe")
    boot.add_argument("--probe-uuid", help="reuse an existing id (default: generate one)")
    tmpl = panel_sub.add_parser("client-template", help="upload the leak-resistant Xray template")
    tmpl.add_argument("--name", default="shahrah-leak-resistant")
    tmpl.add_argument(
        "--make-default", action="store_true", help="apply to ALL users (explicit choice)"
    )
    sales = panel_sub.add_parser("sales-role", help="create a least-privilege sales role")
    sales.add_argument("--name", required=True)
    sales.add_argument("--template-id", type=int, nargs="+", required=True)
    sales.add_argument("--max-users", type=int)
    sales.add_argument("--data-limit-max-bytes", type=int)
    sales.add_argument("--expire-max-seconds", type=int)

    show = sub.add_parser("print", help="print host files generated for the installer")
    show.add_argument("what", choices=["systemd-unit", "brain-unit", "ufw", "sysctl"])
    show.add_argument("--ssh-port", type=int, default=22)
    return parser


def _validate_with_xray(xray_bin: str, config_text: str) -> None:
    with tempfile.TemporaryDirectory(prefix="shahrah-validate-") as tmp:
        path = Path(tmp) / "xray.json"
        path.write_text(config_text, encoding="utf-8")
        try:
            result = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [xray_bin, "run", "-test", "-c", str(path)],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except FileNotFoundError as exc:
            raise ConfigError(f"xray binary not found: {xray_bin!r}") from exc
    if result.returncode != 0:
        raise ConfigError(f"xray rejected the config:\n{result.stdout}{result.stderr}")


def _write_service_config(path: Path, text: str, group: str | None) -> None:
    write_private_file(path, text)
    if group:
        shutil.chown(path, group=group)
        path.chmod(0o640)


def _run_brain(args: argparse.Namespace) -> int:
    """Wire prober, oracle and panel together. The panel API key is read from the environment
    only: command-line arguments are visible to every local user through the process list."""
    logging.basicConfig(
        level=args.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    config = BrainConfig.from_json(Path(args.config).read_text(encoding="utf-8"))

    panel_sync: PanelSync | None = None
    if args.panel_url:
        client = PanelClient(args.panel_url, os.environ.get("SHAHRAH_PANEL_API_KEY", ""))
        panel_sync = functools.partial(sync, client, path_to_remark=dict(config.remarks))
    else:
        logging.getLogger("shahrah.brain").warning("no --panel-url: observing only")

    session: XrayProbeSession | None = None

    def probe_round() -> list[ProbeResult]:
        nonlocal session
        try:
            if session is None:
                session = XrayProbeSession(args.xray_bin, config.endpoints, config.probe_user)
                session.start()
            return session.probe_all()
        except (ProbeError, OSError) as exc:
            if session is not None:
                session.stop()
            session = None  # a fresh Xray process is started on the next cycle
            raise ProbeError(str(exc)) from exc

    brain = Brain(config, probe_round, panel_sync)
    try:
        if args.once:
            decision = brain.cycle()
            if decision is None:
                return 1
            sys.stdout.write(json.dumps(describe(decision), indent=2) + "\n")
            return 0
        run_forever(brain, config.interval_s)
    except KeyboardInterrupt:
        pass
    finally:
        if session is not None:
            session.stop()
    return 0


def _run_panel(args: argparse.Namespace) -> int:
    if not args.panel_url:
        raise ConfigError("--panel-url (or SHAHRAH_PANEL_URL) is required")
    client = PanelClient(args.panel_url, os.environ.get("SHAHRAH_PANEL_API_KEY", ""))
    try:
        if args.panel_command == "bootstrap":
            probe_uuid = args.probe_uuid or keys.generate_uuid()
            user = User(probe_uuid, args.probe_username)  # validates both values
            role_created = client.ensure_role(brain_role())
            user_created = client.ensure_probe_user(user.label, user.uuid, args.probe_group_id)
            result = {
                "brain_role": "created" if role_created else "already existed",
                "probe_user": {"uuid": user.uuid, "label": user.label},
                "probe_user_state": "created" if user_created else "already existed",
            }
        elif args.panel_command == "client-template":
            created = client.ensure_client_template(
                args.name,
                client_template.dumps(client_template.xray_client_template()),
                make_default=args.make_default,
            )
            result = {
                "client_template": "created" if created else "already existed",
                "is_default": bool(created and args.make_default),
            }
        else:
            role = sales_manager_role(
                args.name,
                allowed_template_ids=args.template_id,
                max_users=args.max_users,
                data_limit_max_bytes=args.data_limit_max_bytes,
                expire_max_seconds=args.expire_max_seconds,
            )
            result = {"sales_role": "created" if client.ensure_role(role) else "already existed"}
    except PanelError as exc:
        raise ConfigError(str(exc)) from exc
    sys.stdout.write(json.dumps(result, indent=2) + "\n")
    return 0


def _run(args: argparse.Namespace) -> int:
    state_path: Path = args.state
    out = sys.stdout

    if args.command == "init":
        if state_path.exists() and not args.force:
            raise ConfigError(f"{state_path} already exists (use --force to replace it)")
        state = NodeState.create(
            public_host=args.host,
            target_host=args.target,
            profile=Profile(args.profile),
            port=args.port,
            allow_non_443=args.allow_non_443,
        )
        save_state(state_path, state)
        out.write(f"node initialised: {state_path}\npublic key: {state.public_key}\n")
        return 0

    if args.command == "print":
        if args.what == "systemd-unit":
            out.write(deploy.systemd_unit())
        elif args.what == "brain-unit":
            out.write(deploy.brain_unit())
        elif args.what == "sysctl":
            out.write(deploy.sysctl_conf())
        else:
            ports = [load_state(state_path).port]
            out.write("\n".join(deploy.ufw_commands(ssh_port=args.ssh_port, public_ports=ports)))
            out.write("\n")
        return 0

    if args.command == "brain":
        return _run_brain(args)
    if args.command == "panel":
        return _run_panel(args)

    state = load_state(state_path)

    if args.command == "apply":
        if not state.users:
            raise ConfigError("no users yet: run `shahrah user add <label>` first")
        text = dumps(render_server_config(state.server_settings(), list(state.users)))
        if not args.no_validate:
            _validate_with_xray(args.xray_bin, text)
        _write_service_config(args.config_out, text, args.group)
        out.write(f"wrote {args.config_out} ({len(state.users)} users)\n")
        return 0

    if args.command == "user":
        if args.user_command == "add":
            new_state, user = state.with_user(args.label)
            save_state(state_path, new_state)
            out.write(f"{user.label} {user.uuid}\n")
        elif args.user_command == "remove":
            save_state(state_path, state.without_user(args.label))
            out.write(f"removed {args.label}\n")
        else:
            for user in state.users:
                out.write(f"{user.label} {user.uuid}\n")
        return 0

    user_obj = state.find_user(args.label)
    endpoint = state.endpoint(args.name)
    if args.command == "link":
        out.write(vless_link(endpoint, user_obj) + "\n")
    elif args.command == "sub":
        out.write(build_subscription([endpoint], user_obj) + "\n")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        return _run(args)
    except ConfigError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
