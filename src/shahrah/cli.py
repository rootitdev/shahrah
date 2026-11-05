"""``shahrah`` command line: initialise a node, manage users, render configs and subscriptions."""

from __future__ import annotations

import argparse
import dataclasses
import functools
import json
import logging
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TextIO

from . import (
    accounting,
    capacity,
    client_template,
    deploy,
    hysteria2,
    keys,
    leakcheck,
    loadtest,
    nodecheck,
    ops,
    paqet,
    provision,
    readycheck,
    settle,
    sni_bank,
    sni_scout,
    sni_watch,
    subserve,
    tactics,
    vantage,
    warp,
    waterwall,
)
from . import soak as soakmod
from .brain import Brain, BrainConfig, PanelSync, describe, run_forever
from .links import build_subscription, vless_link
from .models import ConfigError, Listener, Profile, User
from .panel import PanelClient, PanelError, sync
from .prober import (
    ProbeError,
    ProbeResult,
    ProbeTarget,
    XrayProbeSession,
    probe_socks,
    probe_weighted,
)
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
        "--profile",
        choices=[p.value for p in Profile if p is not Profile.CDN_XHTTP],
        default=Profile.REALITY_VISION,
    )
    init.add_argument("--port", type=int, default=443)
    init.add_argument("--allow-non-443", action="store_true", help="allow ports outside 443/80/53")
    init.add_argument(
        "--extra-listener",
        action="append",
        default=[],
        metavar="PORT:PROFILE",
        help="additional port, e.g. 80:reality-xhttp or "
        "8080:cdn-xhttp:cdn.example.com[:PATH[:http]] (repeatable)",
    )
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

    listener = sub.add_parser("listener", help="manage extra listening ports")
    listener_sub = listener.add_subparsers(dest="listener_command", required=True)
    l_add = listener_sub.add_parser("add")
    l_add.add_argument("spec", metavar="PORT:PROFILE")
    l_remove = listener_sub.add_parser("remove")
    l_remove.add_argument("port", type=int)
    listener_sub.add_parser("list")

    link = sub.add_parser("link", help="print the vless:// link(s) for a user")
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
    brain.add_argument(
        "--social-probe",
        action="store_true",
        help="judge paths by weighted Instagram reachability/latency instead of one 204 URL",
    )
    brain.add_argument(
        "--paqet-unit",
        default="",
        help="systemd unit of the paqet client to start in restricted/outage mode",
    )
    brain.add_argument(
        "--control-report",
        default=os.environ.get("SHAHRAH_CONTROL_REPORT", ""),
        help="path or https URL of the control-vantage report (or SHAHRAH_CONTROL_REPORT)",
    )
    brain.add_argument("--control-max-age", type=float, default=300.0, help="seconds")
    brain.add_argument(
        "--on-burn",
        type=Path,
        default=Path(p) if (p := os.environ.get("SHAHRAH_ON_BURN", "")) else None,
        help="executable run on burn (or SHAHRAH_ON_BURN); names only, no shell",
    )
    brain.add_argument(
        "--write-report",
        type=Path,
        default=Path(p) if (p := os.environ.get("SHAHRAH_WRITE_REPORT", "")) else None,
        help="publish this vantage's results (or SHAHRAH_WRITE_REPORT)",
    )
    brain.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING"])

    probe_cmd = sub.add_parser(
        "probe",
        help="fetch HTTPS destinations through brain.json tunnels (Iran-path smoke)",
    )
    probe_cmd.add_argument("--config", type=Path, required=True, help="brain JSON config")
    probe_cmd.add_argument("--xray-bin", default=shutil.which("xray") or "xray")
    probe_cmd.add_argument(
        "--dest",
        action="append",
        default=[],
        metavar="HOST[/PATH]",
        help="repeatable; default: gstatic generate_204 + instagram + telegram",
    )
    probe_cmd.add_argument(
        "--endpoint",
        action="append",
        default=[],
        help="limit to these endpoint names (default: all in config)",
    )
    probe_cmd.add_argument(
        "--wave",
        type=int,
        default=0,
        help="also run N concurrent fetches through the first healthy endpoint",
    )
    probe_cmd.add_argument("--json", action="store_true")

    soak_cmd = sub.add_parser(
        "soak",
        help="sustained fetches through one tunnel (social/AI soak evidence)",
    )
    soak_cmd.add_argument("--config", type=Path, required=True, help="brain JSON config")
    soak_cmd.add_argument("--xray-bin", default=shutil.which("xray") or "xray")
    soak_cmd.add_argument(
        "--endpoint",
        default="",
        help="endpoint name (default: first 443, else first in config)",
    )
    soak_cmd.add_argument(
        "--dest",
        action="append",
        default=[],
        metavar="HOST[/PATH]",
        help="repeatable; default social+AI set",
    )
    soak_cmd.add_argument("--workers", type=int, default=50)
    soak_cmd.add_argument("--duration", type=float, default=300.0, help="seconds (min 30)")
    soak_cmd.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="pause between fetches per worker",
    )
    soak_cmd.add_argument(
        "--progress-file",
        type=Path,
        help="rewrite JSON progress here every ~30s (long soaks)",
    )
    soak_cmd.add_argument("--json", action="store_true")

    leak = sub.add_parser(
        "leakcheck",
        help="static leak-resistance checks on the client template (not a phone TUN test)",
    )
    leak.add_argument(
        "--file",
        type=Path,
        help="Xray client JSON to check (default: built-in leak-resistant template)",
    )
    leak.add_argument("--json", action="store_true")

    ready = sub.add_parser(
        "ready-check",
        help="validate a ready-client subscription body (base64 or vless lines)",
    )
    ready.add_argument(
        "--file",
        type=Path,
        help="subscription file (default: stdin)",
    )
    ready.add_argument("--json", action="store_true")
    ready.add_argument(
        "--sni-dns",
        action="store_true",
        help="also check every REALITY link's SNI resolves near its server IP (bbs#668)",
    )
    ready.add_argument(
        "--strict-sni", action="store_true", help="--sni-dns: accept only own-domain"
    )
    ready.add_argument(
        "--sni-bank",
        type=Path,
        help="fail links whose SNI is unknown, expired or low-scoring in this SNI bank",
    )

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
    tmpl.add_argument(
        "--update",
        action="store_true",
        help="replace content if the name already exists (default: refuse overwrite)",
    )
    prov = panel_sub.add_parser(
        "provision",
        help="create the core config and one host per listener from this node's state",
    )
    prov.add_argument("--core-name", default="shahrah")
    prov.add_argument("--prefix", default="main", help="endpoint/host remark prefix")
    prov.add_argument("--dry-run", action="store_true", help="print the plan, change nothing")
    prov.add_argument(
        "--update-core",
        action="store_true",
        help="replace an existing core config when listeners change (does not restart nodes)",
    )
    prov.add_argument(
        "--restart-nodes",
        action="store_true",
        help="with --update-core, ask the panel to restart its managed nodes",
    )
    sales = panel_sub.add_parser("sales-role", help="create a least-privilege sales role")
    sales.add_argument("--name", required=True)
    sales.add_argument(
        "--template-id",
        type=int,
        nargs="+",
        default=[],
        help="plan template ids; omit with --auto-template to use the first panel template",
    )
    sales.add_argument(
        "--auto-template",
        action="store_true",
        help="pick the first /api/user_templates id when --template-id is omitted",
    )
    sales.add_argument("--max-users", type=int)
    sales.add_argument("--data-limit-max-bytes", type=int)
    sales.add_argument("--expire-max-seconds", type=int)

    show = sub.add_parser("print", help="print host files generated for the installer")
    show.add_argument(
        "what", choices=["systemd-unit", "brain-unit", "serve-sub-unit", "ufw", "sysctl"]
    )
    show.add_argument("--ssh-port", type=int, default=22)

    rotate = sub.add_parser(
        "rotate-reality",
        help="replace the REALITY private key (breaks existing client links until re-issued)",
    )
    rotate.add_argument(
        "--keep-short-id",
        action="store_true",
        help="reuse the current short id (default: generate a new one)",
    )

    scout = sub.add_parser(
        "sni-scout",
        help="rank candidate TLS sites for use as a REALITY target (run on the exit)",
    )
    scout.add_argument(
        "hosts",
        nargs="*",
        help="domain names to probe (omit with --defaults)",
    )
    scout.add_argument(
        "--defaults",
        action="store_true",
        help="probe the built-in REALITY candidate list",
    )
    scout.add_argument("--timeout", type=float, default=5.0)
    scout.add_argument("--allow-risky", action="store_true")
    scout.add_argument(
        "--node-ip",
        help="public node IP: reject targets whose DNS is implausible for it (bbs#668)",
    )
    scout.add_argument(
        "--strict-dns",
        action="store_true",
        help="with --node-ip: accept only an own domain resolving to the node IP",
    )
    scout.add_argument("--json", action="store_true", help="machine-readable output")

    bank = sub.add_parser(
        "sni-bank",
        help="scored, expiring bank of SNI candidates (seed/add/refresh/list/rotate/vantage)",
    )
    bank.add_argument(
        "--bank", type=Path, default=None, help="bank file (default: next to the state file)"
    )
    bank.add_argument("--ttl-hours", type=float, default=sni_bank.DEFAULT_TTL_S / 3600)
    bsub = bank.add_subparsers(dest="bank_command", required=True)
    b_seed = bsub.add_parser("seed", help="add the built-in Iran + foreign seed names")
    b_seed.add_argument("--node-ip", help="public IP the SNI must be plausible for")
    b_add = bsub.add_parser("add", help="add candidate domain names")
    b_add.add_argument("hosts", nargs="+")
    b_add.add_argument("--region", choices=sni_bank.REGIONS, default="foreign")
    b_add.add_argument("--node-ip", help="public IP the SNI must be plausible for")
    b_ref = bsub.add_parser("refresh", help="re-verify due candidates from this host (the exit)")
    b_ref.add_argument("--all", action="store_true", help="re-verify everything, not just due")
    b_ref.add_argument("--timeout", type=float, default=5.0)
    b_list = bsub.add_parser("list", help="score and list candidates, best first")
    b_list.add_argument("--region", choices=sni_bank.REGIONS)
    b_list.add_argument("--strict-dns", action="store_true")
    b_list.add_argument("--json", action="store_true")
    b_rot = bsub.add_parser("rotate", help="say (or --apply) whether the active SNI should move")
    b_rot.add_argument("--region", choices=sni_bank.REGIONS, default="foreign")
    b_rot.add_argument("--apply", action="store_true", help="record the pick as active")
    b_rep = bsub.add_parser("report", help="write this vantage's SNI report (run in Iran)")
    b_rep.add_argument("--vantage", required=True)
    b_rep.add_argument("--asn", type=int)
    b_rep.add_argument("--timeout", type=float, default=5.0)
    b_rep.add_argument("--out", type=Path, required=True)
    b_merge = bsub.add_parser("merge", help="fold vantage SNI reports into the bank")
    b_merge.add_argument("reports", nargs="+", type=Path)

    retarget = sub.add_parser(
        "retarget", help="change the REALITY target / SNI (then apply + restart)"
    )
    retarget.add_argument("target", help="TLS 1.3 domain the server will imitate")

    ops_cmd = sub.add_parser(
        "ops", help="unified ops console (status, SNI scout/watch, usage, ig-mult)"
    )
    ops_cmd.add_argument("--listen", default="127.0.0.1:8787", help="host:port (default loopback)")
    ops_cmd.add_argument(
        "--token",
        default=os.environ.get("SHAHRAH_OPS_TOKEN", ""),
        help="shared secret (or SHAHRAH_OPS_TOKEN); required",
    )
    ops_cmd.add_argument(
        "--brain-status",
        type=Path,
        help="optional JSON file with a brain describe() snapshot",
    )
    ops_cmd.add_argument(
        "--access-log",
        type=Path,
        help="Xray access log path for live SNI watch / ig-mult shares in the ops UI",
    )
    ops_cmd.add_argument(
        "--watchlist",
        type=Path,
        help="optional domain watchlist for SNI watch filtering",
    )
    ops_cmd.add_argument(
        "--retention-hours",
        type=float,
        default=48.0,
        help="SNI watch retention when serving /api/sni-watch (default 48)",
    )
    ops_cmd.add_argument(
        "--stats-server",
        default="",
        help="loopback StatsService host:port for /api/usage (e.g. 127.0.0.1:10085)",
    )
    ops_cmd.add_argument("--xray-bin", default="xray", help="binary for statsquery")
    ops_cmd.add_argument(
        "--ig-mult-config",
        type=Path,
        default=None,
        help="JSON path for Instagram billing multiplier (created on first save)",
    )
    ops_cmd.add_argument(
        "--print-token",
        action="store_true",
        help="generate a token, print it, and exit (for first-time setup)",
    )

    access = sub.add_parser(
        "access-log",
        help="enable/disable the Xray access log (required for SNI watch; off by default)",
    )
    access.add_argument(
        "path",
        nargs="?",
        default="",
        help="absolute log path, or omit with --off",
    )
    access.add_argument("--off", action="store_true", help="disable access logging again")

    stats = sub.add_parser(
        "stats-api",
        help="enable/disable loopback StatsService (required for usage; off by default)",
    )
    stats.add_argument(
        "port",
        nargs="?",
        type=int,
        default=0,
        help="loopback port (default 10085 when enabling)",
    )
    stats.add_argument("--off", action="store_true", help="disable the stats API again")

    usage = sub.add_parser(
        "usage",
        help="print per-user traffic from the local Xray StatsService",
    )
    usage.add_argument("--xray-bin", default="xray")
    usage.add_argument(
        "--server",
        default="",
        help="host:port of StatsService (default 127.0.0.1:<stats_api_port>)",
    )
    usage.add_argument("--reset", action="store_true", help="reset counters after reading")
    usage.add_argument("--json", action="store_true", help="machine-readable output")

    watch = sub.add_parser("sni-watch", help="aggregate destinations from an Xray access log")
    watch.add_argument("--log", type=Path, required=True, help="access log file")
    watch.add_argument("--watchlist", type=Path, help="optional domain list to filter")
    watch.add_argument("--retention-hours", type=float, default=48.0)

    sub_cmd = sub.add_parser(
        "serve-sub",
        help="serve base64 subscriptions for ready-made clients (secret URL path)",
    )
    sub_cmd.add_argument("--listen", default="127.0.0.1:8788")
    sub_cmd.add_argument(
        "--path-secret",
        default=os.environ.get("SHAHRAH_SUB_SECRET", ""),
        help="unguessable path segment (or SHAHRAH_SUB_SECRET)",
    )
    sub_cmd.add_argument(
        "--print-secret", action="store_true", help="generate a path secret and exit"
    )
    sub_cmd.add_argument(
        "--tactics",
        type=Path,
        help="signed tactics envelope (tactics-sign) served at /<secret>/<label>/tactics",
    )

    tprof = sub.add_parser(
        "tuning-profile",
        help="pick an Xray tuning preset (social = many short flows, Instagram first)",
    )
    tprof.add_argument("name", nargs="?", help="default or social (omit to show)")

    pq = sub.add_parser(
        "paqet-config",
        help="render a paqet (raw-packet crisis path) server/client config, or its iptables",
    )
    pq.add_argument("role", choices=["server", "client", "firewall", "unit"])
    pq.add_argument("--interface", default="eth0")
    pq.add_argument("--ip", help="this host's IPv4 on --interface")
    pq.add_argument("--router-mac", default="")
    pq.add_argument("--server-ip", help="client: paqet server IPv4")
    pq.add_argument("--port", type=int, default=9999)
    pq.add_argument("--key-file", type=Path, help="shared KCP key (created if missing)")
    pq.add_argument("--unit-role", choices=["server", "client"], default="server")
    pq.add_argument("--config-path", default="/etc/shahrah/paqet.yaml")
    pq.add_argument("--out", type=Path, help="write the config here (mode 0600)")

    hy = sub.add_parser(
        "hysteria2",
        help="Hysteria2 QUIC/UDP social path: enable, render configs, port-hop rules, unit",
    )
    hy.add_argument(
        "action",
        choices=["enable", "disable", "show", "server", "client", "hop-rules", "unit"],
    )
    hy.add_argument("--port", type=int, default=8443, help="UDP listen port")
    hy.add_argument("--hop", default="", help="UDP port-hopping range, e.g. 20000-40000")
    hy.add_argument("--sni", default="", help="certificate name (default: public host)")
    hy.add_argument("--cert", type=Path, help="enable: PEM to pin (self-signed certificate)")
    hy.add_argument("--cert-path", default="/etc/shahrah/hy2.crt")
    hy.add_argument("--key-path", default="/etc/shahrah/hy2.key")
    hy.add_argument("--tuning", choices=sorted(hysteria2.TUNING), default="social")
    hy.add_argument("--label", default="", help="client: user label")
    hy.add_argument("--socks", default="127.0.0.1:1081", help="client: loopback SOCKS listen")
    hy.add_argument("--interface", default="eth0", help="hop-rules: public interface")
    hy.add_argument("--unit-role", choices=["server", "client"], default="server")
    hy.add_argument("--config-path", default="/etc/shahrah/hysteria2.yaml")
    hy.add_argument("--out", type=Path, help="write the config here (mode 0600)")

    wp = sub.add_parser(
        "warp",
        help="Cloudflare WARP egress for Google-family destinations (wgcf WireGuard)",
    )
    wp.add_argument(
        "action",
        choices=["enable", "disable", "show", "wg-conf", "unit"],
    )
    wp.add_argument(
        "--profile",
        type=Path,
        help="enable: path to a wgcf-generated WireGuard profile",
    )
    wp.add_argument(
        "--route-all",
        action="store_true",
        help="send all egress through WARP (not only Google-family)",
    )
    wp.add_argument("--interface", default="warp", help="wg-quick interface name (Hy2 bindDevice)")
    wp.add_argument("--out", type=Path, help="wg-conf/unit: write here (mode 0600)")

    nc = sub.add_parser(
        "node-check",
        help="read-only node readiness checks learned from past outages (DIAG_LESSONS.md)",
    )
    nc.add_argument("--cert", type=Path, help="PEM whose pin to verify (with --pin)")
    nc.add_argument("--pin", default="", help="sha256 pin clients use (hex)")
    nc.add_argument("--no-target", action="store_true", help="skip the REALITY target probe")
    nc.add_argument("--json", action="store_true")

    wwp = sub.add_parser(
        "waterwall-config",
        help="render the WaterWall Iran<->exit backhaul (config.json + core.json) or its unit",
    )
    wwp.add_argument("side", choices=["iran", "exit", "unit"])
    wwp.add_argument("--iran-ip", default="")
    wwp.add_argument("--exit-ip", default="")
    wwp.add_argument("--key-file", type=Path, help="shared Reality secret (created if missing)")
    wwp.add_argument("--mode", choices=sorted(waterwall.MODES), default="reverse")
    wwp.add_argument("--user-port", type=int, action="append", help="repeatable (default 443)")
    wwp.add_argument("--tunnel-port", type=int, default=8443)
    wwp.add_argument("--exit-service", default="127.0.0.1:443", help="Xray on the exit")
    wwp.add_argument("--cover-sni", default="www.speedtest.net")
    wwp.add_argument("--cover-addr", default="", help="pinned cover IP (skip DNS per handshake)")
    wwp.add_argument("--pool", type=int, default=8, help="reverse: idle warm connections")
    wwp.add_argument(
        "--no-verify-cover", action="store_true", help="cover uses a private CA (labs only)"
    )
    wwp.add_argument("--open-peer", action="store_true", help="do not whitelist the peer IP")
    wwp.add_argument("--workdir", default="/etc/shahrah/waterwall")
    wwp.add_argument("--out-dir", type=Path, help="write config.json/core.json here (0600)")

    tsign = sub.add_parser(
        "tactics-sign",
        help="sign per-ASN tactics profiles (key from SHAHRAH_TACTICS_KEY, hex)",
    )
    tsign.add_argument("profiles", type=Path, help="JSON list of tactics profiles")
    tsign.add_argument("--serial", type=int, required=True)
    tsign.add_argument("--kid", default="k1")
    tsign.add_argument("--ttl-days", type=float, default=7.0)
    tsign.add_argument("--out", type=Path, required=True)

    cap = sub.add_parser(
        "capacity",
        help="recommend Tuning / RAM for a target concurrent-user count",
    )
    cap.add_argument("--users", type=int, required=True, help="e.g. 1000, 2000, 3000")
    cap.add_argument("--json", action="store_true")

    settle_cmd = sub.add_parser(
        "settle-hook",
        help="HMAC payment webhook that credits PasarGuard users (loopback)",
    )
    settle_cmd.add_argument("--listen", default="127.0.0.1:8790")
    settle_cmd.add_argument(
        "--secret",
        default=os.environ.get("SHAHRAH_SETTLE_SECRET", ""),
        help="HMAC secret (or SHAHRAH_SETTLE_SECRET)",
    )
    settle_cmd.add_argument(
        "--panel-url", default=os.environ.get("SHAHRAH_PANEL_URL"), help="PasarGuard base URL"
    )
    settle_cmd.add_argument(
        "--print-secret", action="store_true", help="generate an HMAC secret and exit"
    )
    settle_cmd.add_argument(
        "--emit-curl",
        metavar="USERNAME",
        help="print a signed curl for a 1-day credit (provider integration smoke)",
    )
    settle_cmd.add_argument(
        "--days", type=float, default=1.0, help="with --emit-curl: days to credit"
    )

    load_cmd = sub.add_parser(
        "load-test",
        help="concurrent REALITY tunnel load on loopback (capacity evidence)",
    )
    load_cmd.add_argument(
        "--connections",
        type=int,
        default=300,
        help=f"concurrent tunnels ({loadtest.MIN_CONNECTIONS}-{loadtest.MAX_CONNECTIONS})",
    )
    load_cmd.add_argument("--xray-bin", default=shutil.which("xray") or "xray")
    load_cmd.add_argument(
        "--target",
        default=loadtest.DEFAULT_TARGET,
        help="REALITY cover site (must be reachable on 443)",
    )
    load_cmd.add_argument("--idle-s", type=int, default=loadtest.DEFAULT_IDLE_S)
    load_cmd.add_argument("--json", action="store_true")
    load_cmd.add_argument(
        "--skip-reap",
        action="store_true",
        help="do not wait for idle connection reaping (faster smoke)",
    )
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


def _parse_listener(spec: str) -> Listener:
    """Parse ``PORT:PROFILE`` or, for a CDN listener, ``PORT:cdn-xhttp:HOST[:PATH[:http]]``.

    An empty PATH generates a random unguessable one; a trailing ``http`` means clients reach
    the edge without TLS (port 80).
    """
    port_text, _, rest = spec.partition(":")
    profile_text, _, cdn_text = rest.partition(":")
    try:
        profile = Profile(profile_text)
        if profile is not Profile.CDN_XHTTP:
            if cdn_text:
                raise ConfigError(f"unexpected extra fields for {profile_text}: {cdn_text!r}")
            return Listener(int(port_text), profile)
        host, _, tail = cdn_text.partition(":")
        path_text, _, scheme = tail.partition(":")
        if scheme not in ("", "http", "https"):
            raise ConfigError(f"edge scheme must be http or https: {scheme!r}")
        path = f"/{path_text.lstrip('/')}" if path_text else f"/{secrets.token_urlsafe(12)}"
        return Listener(
            int(port_text),
            profile,
            xhttp_path=path,
            xhttp_mode="packet-up",
            cdn_host=host,
            edge_tls=scheme != "http",
        )
    except ValueError as exc:
        if isinstance(exc, ConfigError):
            raise
        choices = ", ".join(p.value for p in Profile)
        raise ConfigError(
            f"listener must look like PORT:PROFILE ({choices}); got {spec!r}"
        ) from exc

def _burn_hook(executable: Path) -> Callable[[Sequence[str]], None]:
    """Build the on-burn hook. The operator script receives endpoint names only (validated
    labels, never shell-interpreted) and is bounded by a timeout."""
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ConfigError(f"--on-burn is not an executable file: {executable}")

    def hook(names: Sequence[str]) -> None:
        subprocess.run(  # noqa: S603 - fixed operator-chosen executable, no shell
            [str(executable), *names], check=False, timeout=60, stdin=subprocess.DEVNULL
        )

    return hook


def _panel_client(panel_url: str) -> PanelClient:
    """Build a panel client; API key and TLS lab flags come from the environment only."""
    insecure = os.environ.get("SHAHRAH_PANEL_INSECURE_TLS", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    return PanelClient(
        panel_url,
        os.environ.get("SHAHRAH_PANEL_API_KEY", ""),
        insecure_tls=insecure,
    )


def _probe_destinations(specs: Sequence[str]) -> list[ProbeTarget]:
    """Parse ``host`` or ``host/path`` into ProbeTargets (TLS/443, accept common statuses)."""
    if not specs:
        # Social + AI fronts (product hostnames only — not deployment identifiers).
        common = frozenset({200, 301, 302, 403})
        return [
            ProbeTarget(),
            ProbeTarget("www.instagram.com", path="/", expect_status=frozenset({200, 301, 302})),
            ProbeTarget("telegram.org", path="/", expect_status=frozenset({200, 301, 302, 404})),
            ProbeTarget("chatgpt.com", path="/", expect_status=common),
            ProbeTarget("claude.ai", path="/", expect_status=common),
        ]
    out: list[ProbeTarget] = []
    for spec in specs:
        host, _, path = spec.partition("/")
        host = host.strip().lower().rstrip(".")
        path = ("/" + path) if path else "/"
        if not host or "/" in host or host.startswith("."):
            raise ConfigError(f"bad --dest {spec!r}")
        expect = frozenset({204}) if path == "/generate_204" else frozenset({200, 301, 302, 403})
        out.append(ProbeTarget(host, path=path, expect_status=expect))
    return out


def _run_soak(args: argparse.Namespace) -> int:
    config = BrainConfig.from_json(Path(args.config).read_text(encoding="utf-8"))
    endpoints = list(config.endpoints)
    if args.endpoint:
        endpoints = [e for e in endpoints if e.name == args.endpoint]
        if not endpoints:
            raise ConfigError(f"unknown endpoint {args.endpoint!r}")
    preferred = next((e for e in endpoints if e.port == 443), endpoints[0] if endpoints else None)
    if preferred is None:
        raise ConfigError("no endpoints to soak")
    dests = _probe_destinations(args.dest) if args.dest else list(soakmod.DEFAULT_SOAK_TARGETS)
    soak_cfg = soakmod.SoakConfig(
        workers=args.workers,
        duration_s=args.duration,
        interval_s=args.interval,
    )
    xray_bin = args.xray_bin
    if not Path(xray_bin).exists() and shutil.which(xray_bin):
        xray_bin = shutil.which(xray_bin) or xray_bin
    progress_cb = None
    if args.progress_file is not None:

        def progress_cb(payload: dict) -> None:
            soakmod.write_progress_file(args.progress_file, payload)

    with XrayProbeSession(xray_bin, [preferred], config.probe_user) as session:
        report = soakmod.run_soak(
            session,
            preferred.name,
            dests,
            soak_cfg,
            on_progress=progress_cb,
        )
    data = report.as_dict()
    if args.json:
        sys.stdout.write(json.dumps(data, indent=2) + "\n")
    else:
        sys.stdout.write(
            f"soak {data['endpoint']} workers={data['workers']} "
            f"{data['duration_s']}s  ok={data['ok']}/{data['attempts']} "
            f"rate={data['success_rate']:.4f}  p50={data['p50_ms']}ms "
            f"p95={data['p95_ms']}ms  xray_died={data['xray_died']}\n"
        )
        for host, counts in data["by_host"].items():
            sys.stdout.write(f"  {host}: ok={counts['ok']} fail={counts['fail']}\n")
    if report.xray_died or report.attempts == 0:
        return 3
    if report.ok / report.attempts < 0.95:
        return 2
    return 0


def _run_probe(args: argparse.Namespace) -> int:
    config = BrainConfig.from_json(Path(args.config).read_text(encoding="utf-8"))
    endpoints = list(config.endpoints)
    if args.endpoint:
        wanted = set(args.endpoint)
        endpoints = [e for e in endpoints if e.name in wanted]
        missing = wanted - {e.name for e in endpoints}
        if missing:
            raise ConfigError(f"unknown endpoints: {sorted(missing)}")
    if not endpoints:
        raise ConfigError("no endpoints to probe")
    dests = _probe_destinations(args.dest)
    xray_bin = args.xray_bin
    if not Path(xray_bin).exists() and shutil.which(xray_bin):
        xray_bin = shutil.which(xray_bin) or xray_bin
    payload: dict[str, object] = {"destinations": [], "wave": None}
    with XrayProbeSession(xray_bin, endpoints, config.probe_user) as session:
        for dest in dests:
            rows = [
                {
                    "endpoint": r.endpoint,
                    "ok": r.ok,
                    "latency_ms": r.latency_ms,
                    "detail": r.detail,
                }
                for r in session.probe_all(timeout=15.0, target=dest)
            ]
            payload["destinations"].append({"host": dest.host, "path": dest.path, "results": rows})
        if args.wave > 0:
            # Prefer 443, then first endpoint that just succeeded on the default target.
            preferred = next((e.name for e in endpoints if e.port == 443), endpoints[0].name)
            payload["wave"] = session.wave(preferred, args.wave, timeout=20.0)
    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        for block in payload["destinations"]:  # type: ignore[assignment]
            if not isinstance(block, dict):
                continue
            sys.stdout.write(f"# {block['host']}{block['path']}\n")
            for row in block["results"]:  # type: ignore[index]
                status = "ok" if row["ok"] else f"FAIL {row.get('detail') or ''}"
                ms = row["latency_ms"]
                sys.stdout.write(f"  {row['endpoint']}: {status}" + (f" {ms}ms\n" if ms else "\n"))
        wave = payload["wave"]
        if isinstance(wave, dict):
            sys.stdout.write(
                f"wave {wave['endpoint']}: {wave['ok']}/{wave['requested']}  "
                f"p50={wave['p50_ms']}ms p95={wave['p95_ms']}ms\n"
            )
    # Fail if any destination/endpoint pair failed (except filtered TCP/53).
    failed = [
        (block["host"], row["endpoint"])
        for block in payload["destinations"]  # type: ignore[union-attr]
        for row in block["results"]
        if not row["ok"] and not str(row["endpoint"]).endswith("-53")
    ]
    return 2 if failed else 0


def _run_brain(args: argparse.Namespace) -> int:
    """Wire prober, oracle and panel together. The panel API key is read from the environment
    only: command-line arguments are visible to every local user through the process list."""
    logging.basicConfig(
        level=args.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    config = BrainConfig.from_json(Path(args.config).read_text(encoding="utf-8"))

    panel_sync: PanelSync | None = None
    if args.panel_url:
        client = _panel_client(args.panel_url)
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
            live = session
            ports = {s.name: s.socks_port for s in config.sidecars}

            def fetch(name: str, target: ProbeTarget | None) -> ProbeResult:
                if name in ports:  # hysteria2 / paqet client on a loopback SOCKS port
                    return probe_socks(name, ports[name], target)
                return live.probe(name, 8.0, target=target)

            def one(name: str) -> ProbeResult:
                if args.social_probe:
                    return probe_weighted(name, lambda t: fetch(name, t))
                return fetch(name, None)

            names = [ep.name for ep in config.endpoints] + list(ports)
            with ThreadPoolExecutor(max_workers=len(names)) as pool:
                return list(pool.map(one, names))
        except (ProbeError, OSError) as exc:
            if session is not None:
                session.stop()
            session = None  # a fresh Xray process is started on the next cycle
            raise ProbeError(str(exc)) from exc

    on_burn = _burn_hook(args.on_burn) if args.on_burn else None
    control_report = (args.control_report or "").strip()
    control_source = (
        vantage.make_control_source(control_report, max_age_s=args.control_max_age)
        if control_report
        else None
    )
    report_sink = None
    if args.write_report is not None:
        report_path = args.write_report

        def report_sink(results: Sequence[ProbeResult]) -> None:
            vantage.write_report(report_path, vantage.build_report(results))

    brain = Brain(
        config,
        probe_round,
        panel_sync,
        control_source=control_source,
        on_burn=on_burn,
        report_sink=report_sink,
        on_mode_change=paqet.crisis_hook(args.paqet_unit) if args.paqet_unit else None,
    )
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


def _provision_summary(
    args: argparse.Namespace,
    plans: list[provision.HostPlan],
    core_created: bool | None,
    hosts: dict[str, bool],
) -> dict[str, object]:
    """Secret-free report; ``brain_remarks`` goes straight into the brain config."""
    return {
        "core": {
            "name": args.core_name,
            "state": "planned" if core_created is None else "created" if core_created else "exists",
        },
        "hosts": {
            plan.remark: "planned"
            if core_created is None
            else "created"
            if hosts[plan.remark]
            else "exists"
            for plan in plans
        },
        "brain_remarks": provision.remarks(plans),
    }


def _run_panel(args: argparse.Namespace) -> int:
    if args.panel_command == "provision" and args.dry_run:
        # A dry run needs no URL or credentials and never talks to the panel.
        plans = provision.host_plans(load_state(args.state), prefix=args.prefix)
        sys.stdout.write(json.dumps(_provision_summary(args, plans, None, {}), indent=2) + "\n")
        return 0
    if not args.panel_url:
        raise ConfigError("--panel-url (or SHAHRAH_PANEL_URL) is required")
    client = _panel_client(args.panel_url)
    try:
        if args.panel_command == "provision":
            state = load_state(args.state)
            plans = provision.host_plans(state, prefix=args.prefix)
            payload = provision.core_payload(args.core_name, state)
            core_created = client.ensure_core(payload)
            core_state = "created" if core_created else "exists"
            if not core_created and args.update_core:
                client.update_core(payload, restart_nodes=args.restart_nodes)
                core_state = "updated"
            hosts = {plan.remark: client.ensure_host(plan.payload) for plan in plans}
            result = _provision_summary(args, plans, core_created, hosts)
            result["core"]["state"] = core_state
        elif args.panel_command == "bootstrap":
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
            body = client_template.dumps(client_template.xray_client_template())
            if args.update:
                state = client.upsert_client_template(
                    args.name, body, make_default=args.make_default
                )
            else:
                created = client.ensure_client_template(
                    args.name, body, make_default=args.make_default
                )
                state = "created" if created else "already existed"
            result = {
                "client_template": state,
                "is_default": bool(args.make_default and state in {"created", "updated"}),
            }
        else:
            template_ids = list(args.template_id)
            if not template_ids:
                if not args.auto_template:
                    raise ConfigError("pass --template-id or --auto-template")
                templates = client.list_user_templates()
                template_ids = [int(t["id"]) for t in templates if t.get("id") is not None]
                if not template_ids:
                    raise ConfigError("panel has no user templates to bind the sales role to")
                template_ids = template_ids[:1]
            role = sales_manager_role(
                args.name,
                allowed_template_ids=template_ids,
                max_users=args.max_users,
                data_limit_max_bytes=args.data_limit_max_bytes,
                expire_max_seconds=args.expire_max_seconds,
            )
            result = {
                "sales_role": "created" if client.ensure_role(role) else "already existed",
                "template_ids": template_ids,
            }
    except PanelError as exc:
        raise ConfigError(str(exc)) from exc
    sys.stdout.write(json.dumps(result, indent=2) + "\n")
    return 0


def _parse_hop(text: str) -> tuple[int, int] | None:
    if not text:
        return None
    low, sep, high = text.partition("-")
    if not sep or not low.isdigit() or not high.isdigit():
        raise ConfigError(f"--hop must look like 20000-40000: {text!r}")
    return int(low), int(high)



def _run_warp(args: argparse.Namespace, state_path: Path, state: NodeState, out: TextIO) -> int:
    """Enable/disable Cloudflare WARP egress and render the wg-quick profile."""
    if args.action == "enable":
        if args.profile is None:
            raise ConfigError("warp enable needs --profile /path/to/wgcf-profile.conf")
        settings = warp.load_wgcf_profile(args.profile)
        # dataclasses.replace-style via with_warp after rebuilding flags
        from dataclasses import replace as _replace

        settings = _replace(
            settings,
            route_all=bool(args.route_all) or settings.route_all,
            interface=args.interface or settings.interface,
        )
        save_state(state_path, state.with_warp(settings))
        out.write(
            f"warp enabled (iface {settings.interface}; "
            f"{'route-all' if settings.route_all else 'google-family'})\n"
        )
        out.write("next: shahrah apply && systemctl restart shahrah-xray\n")
        out.write(
            "      shahrah warp wg-conf --out /etc/wireguard/warp.conf && "
            "systemctl enable --now wg-quick@warp\n"
        )
        if state.hysteria2 is not None:
            out.write(
                "      shahrah hysteria2 server --out /etc/shahrah/hysteria2.yaml && "
                "systemctl restart shahrah-hysteria2\n"
            )
        return 0
    if args.action == "disable":
        save_state(state_path, state.with_warp(None))
        out.write("warp disabled (re-apply xray / hysteria2 to drop the outbound)\n")
        return 0
    settings = state.warp
    if settings is None:
        raise ConfigError("warp is not enabled: run `shahrah warp enable --profile ...` first")
    if args.action == "show":
        out.write(
            f"interface={settings.interface} endpoint={settings.endpoint} "
            f"address={settings.address_v4} route_all={settings.route_all}\n"
        )
        return 0
    if args.action == "wg-conf":
        text = warp.wg_quick_conf(settings)
        if args.out:
            write_private_file(args.out, text)
            out.write(f"wrote {args.out}\n")
        else:
            out.write(text)
        return 0
    if args.action == "unit":
        # Document-only pointer: standard wg-quick@.service from wireguard-tools.
        text = (
            "# Use the distro unit: systemctl enable --now wg-quick@warp\n"
            "# after writing /etc/wireguard/warp.conf via `shahrah warp wg-conf`.\n"
        )
        if args.out:
            write_private_file(args.out, text)
            out.write(f"wrote {args.out}\n")
        else:
            out.write(text)
        return 0
    raise ConfigError(f"unknown warp action: {args.action}")


def _run_hysteria2(
    args: argparse.Namespace, state_path: Path, state: NodeState, out: TextIO
) -> int:
    action = args.action
    if action == "enable":
        current = state.hysteria2
        settings = hysteria2.Hy2Settings(
            port=args.port,
            obfs_password=current.obfs_password if current else hysteria2.generate_secret(),
            sni=args.sni,
            pin_sha256=hysteria2.cert_pin(args.cert.read_text(encoding="utf-8"))
            if args.cert
            else "",
            hop=_parse_hop(args.hop),
            tuning=args.tuning,
            cert_path=args.cert_path,
            key_path=args.key_path,
        )
        save_state(state_path, state.with_hysteria2(settings))
        out.write(f"hysteria2 enabled on udp/{settings.port} (tuning {settings.tuning})\n")
        return 0
    if action == "disable":
        save_state(state_path, state.with_hysteria2(None))
        out.write("hysteria2 disabled\n")
        return 0
    if action == "unit":
        out.write(hysteria2.systemd_unit(args.unit_role, args.config_path))
        return 0
    settings = state.hysteria2
    if settings is None:
        raise ConfigError("hysteria2 is not enabled: run `shahrah hysteria2 enable` first")
    if action == "show":
        public = {k: v for k, v in settings.to_dict().items() if k != "obfs_password"}
        out.write(json.dumps(public, indent=2) + "\n")
        return 0
    if action == "hop-rules":
        for argv in hysteria2.hop_rules(settings, args.interface):
            out.write(" ".join(argv) + "\n")
        return 0
    if action == "server":
        text = hysteria2.render_server(settings, list(state.users), warp=state.warp)
    else:
        user = state.find_user(args.label) if args.label else state.users[0]
        text = hysteria2.render_client(settings, state.public_host, user, socks_listen=args.socks)
    if args.out:
        write_private_file(args.out, text)
        out.write(f"wrote {args.out}\n")
    else:
        out.write(text)
    return 0


def _run_waterwall(args: argparse.Namespace, out: TextIO) -> int:
    if args.side == "unit":
        out.write(waterwall.systemd_unit(args.workdir))
        return 0
    if not args.iran_ip or not args.exit_ip or args.key_file is None:
        raise ConfigError("--iran-ip, --exit-ip and --key-file are required")
    if not args.key_file.exists():
        write_private_file(args.key_file, secrets.token_urlsafe(18) + "\n")  # 24 chars
    backhaul = waterwall.Backhaul(
        iran_ip=args.iran_ip,
        exit_ip=args.exit_ip,
        password=args.key_file.read_text(encoding="utf-8").strip(),
        cover_sni=args.cover_sni,
        cover_addr=args.cover_addr,
        mode=args.mode,
        user_ports=tuple(args.user_port or [443]),
        tunnel_port=args.tunnel_port,
        exit_service=args.exit_service,
        pool=args.pool,
        restrict_peer=not args.open_peer,
        verify_cover=not args.no_verify_cover,
    )
    cfg = (
        waterwall.render_iran(backhaul) if args.side == "iran" else waterwall.render_exit(backhaul)
    )
    if args.out_dir is None:
        out.write(waterwall.dumps(cfg))
        return 0
    write_private_file(args.out_dir / "config.json", waterwall.dumps(cfg))
    write_private_file(
        args.out_dir / "core.json", waterwall.dumps(waterwall.core_json("config.json"))
    )
    out.write(f"wrote {args.out_dir}/config.json and core.json ({args.side}, {args.mode})\n")
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
            extra_listeners=tuple(_parse_listener(spec) for spec in args.extra_listener),
        )
        save_state(state_path, state)
        out.write(f"node initialised: {state_path}\npublic key: {state.public_key}\n")
        return 0

    if args.command == "print":
        if args.what == "systemd-unit":
            out.write(deploy.systemd_unit())
        elif args.what == "brain-unit":
            out.write(deploy.brain_unit())
        elif args.what == "serve-sub-unit":
            out.write(deploy.serve_sub_unit())
        elif args.what == "sysctl":
            out.write(deploy.sysctl_conf())
        elif args.what == "ufw":
            ports = [item.port for item in load_state(state_path).server_settings().listeners()]
            out.write("\n".join(deploy.ufw_commands(ssh_port=args.ssh_port, public_ports=ports)))
            out.write("\n")
        else:
            raise ConfigError(f"unknown print target: {args.what}")
        return 0

    if args.command == "brain":
        return _run_brain(args)
    if args.command == "leakcheck":
        if args.file is not None:
            payload = json.loads(args.file.read_text(encoding="utf-8"))
        else:
            payload = client_template.xray_client_template()
        report = leakcheck.check_client_template(payload)
        data = report.as_dict()
        if args.json:
            out.write(json.dumps(data, indent=2) + "\n")
        else:
            mark = "PASS" if report.ok else "FAIL"
            out.write(f"leakcheck {mark}\n")
            for item in report.checks:
                flag = "ok" if item["ok"] else "NO"
                detail = f"  {item['detail']}" if item["detail"] else ""
                out.write(f"  {flag} {item['name']}{detail}\n")
        return 0 if report.ok else 2
    if args.command == "ready-check":
        body = args.file.read_text(encoding="utf-8") if args.file is not None else sys.stdin.read()
        report = readycheck.check_subscription(body)
        data = report.as_dict()
        sni_checks = readycheck.check_sni_dns(body) if args.sni_dns else []
        if args.sni_dns:
            data["sni_dns"] = [c.as_dict() for c in sni_checks]
            if any(not c.accepted(strict=args.strict_sni) for c in sni_checks):
                report.ok = False
                data["ok"] = False
        bank_problems = (
            readycheck.check_sni_bank(body, sni_bank.load_bank(args.sni_bank), time.time())
            if args.sni_bank
            else []
        )
        if args.sni_bank:
            data["sni_bank"] = [{"sni": s, "problem": p} for s, p in bank_problems]
            if bank_problems:
                report.ok = False
                data["ok"] = False
        if args.json:
            out.write(json.dumps(data, indent=2) + "\n")
        else:
            mark = "PASS" if report.ok else "FAIL"
            out.write(f"ready-check {mark} links={report.link_count}\n")
            for sni, problem in bank_problems:
                out.write(f"  NO sni-bank {sni}: {problem}\n")
            for item in report.links:
                flag = "ok" if item.ok else "NO"
                detail = f"  {item.detail}" if item.detail else ""
                out.write(f"  {flag} {item.name} ({item.profile}){detail}\n")
            for c in sni_checks:
                flag = "ok" if c.accepted(strict=args.strict_sni) else "NO"
                out.write(f"  {flag} sni-dns {c.sni} @ {c.node_ip}: {c.verdict} {c.detail}\n")
            for note in report.notes:
                out.write(f"note: {note}\n")
        return 0 if report.ok else 2
    if args.command == "probe":
        return _run_probe(args)
    if args.command == "soak":
        return _run_soak(args)
    if args.command == "panel":
        return _run_panel(args)
    if args.command == "ops":
        if args.print_token:
            out.write(ops.generate_token() + "\n")
            return 0
        if not args.token:
            raise ConfigError("pass --token or set SHAHRAH_OPS_TOKEN (or --print-token)")
        host, _, port_text = args.listen.partition(":")
        config = ops.OpsConfig(
            token=args.token,
            host=host or "127.0.0.1",
            port=int(port_text or "8787"),
            brain_status_path=str(args.brain_status) if args.brain_status else None,
            access_log_path=str(args.access_log) if args.access_log else None,
            watchlist_path=str(args.watchlist) if args.watchlist else None,
            retention_hours=args.retention_hours,
            stats_server=args.stats_server or None,
            xray_bin=args.xray_bin,
            ig_mult_path=str(args.ig_mult_config) if args.ig_mult_config else None,
        )
        out.write(f"ops listening on http://{config.host}:{config.port}/ (token required)\n")
        ops.serve(config)
        return 0

    if args.command == "sni-watch":
        store = sni_watch.WatchStore(retention_s=args.retention_hours * 3600)
        store.ingest_file(args.log)
        watchlist = sni_watch.load_watchlist(args.watchlist) if args.watchlist else None
        out.write(json.dumps(store.summary(watchlist=watchlist), indent=2) + "\n")
        return 0

    if args.command == "serve-sub" and args.print_secret:
        out.write(subserve.generate_path_secret() + "\n")
        return 0

    if args.command == "settle-hook" and args.print_secret:
        out.write(secrets.token_urlsafe(32) + "\n")
        return 0

    if args.command == "paqet-config":
        if args.role == "firewall":
            for argv in paqet.server_firewall_rules(args.port):
                out.write(" ".join(argv) + "\n")
            return 0
        if args.role == "unit":
            out.write(paqet.systemd_unit(args.unit_role, args.config_path))
            return 0
        if args.key_file is None or not args.ip:
            raise ConfigError("--ip and --key-file are required")
        if not args.key_file.exists():
            write_private_file(args.key_file, paqet.generate_key() + "\n")
        key = args.key_file.read_text(encoding="utf-8").strip()
        if args.role == "server":
            text = paqet.render_server(
                paqet.PaqetServer(args.interface, args.ip, args.router_mac, key, args.port)
            )
        else:
            if not args.server_ip:
                raise ConfigError("--server-ip is required for the client")
            text = paqet.render_client(
                paqet.PaqetClient(
                    args.interface, args.ip, args.router_mac, args.server_ip, key, args.port
                )
            )
        if args.out is not None:
            write_private_file(args.out, text)
        else:
            out.write(text)
        return 0

    if args.command == "waterwall-config":
        return _run_waterwall(args, out)

    if args.command == "tactics-sign":
        key_hex = os.environ.get("SHAHRAH_TACTICS_KEY", "").strip()
        if not key_hex:
            raise ConfigError("set SHAHRAH_TACTICS_KEY (hex, >= 32 bytes)")
        try:
            key = bytes.fromhex(key_hex)
            items = json.loads(args.profiles.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise ConfigError(f"cannot read key or profiles: {exc}") from exc
        now = int(time.time())
        bundle = tactics.TacticsBundle(
            serial=args.serial,
            issued_at=now,
            expires_at=now + int(args.ttl_days * 86400),
            profiles=tuple(tactics.TacticsProfile.from_dict(item) for item in items),
        )
        envelope = tactics.sign(bundle, key, args.kid)
        write_private_file(args.out, json.dumps(envelope) + "\n")
        out.write(f"signed {len(bundle.profiles)} profiles serial={bundle.serial}\n")
        return 0

    if args.command == "capacity":
        plan = capacity.plan_for_users(args.users)
        if args.json:
            out.write(json.dumps(plan.as_dict(), indent=2) + "\n")
        else:
            t = plan.tuning
            out.write(
                f"users={plan.users}  buffer={t.buffer_size_kb}KiB  "
                f"idle={t.conn_idle_s}s  keepalive={t.tcp_keepalive_idle_s}/"
                f"{t.tcp_keepalive_interval_s}s\n"
                f"xray_rss~{plan.xray_rss_mb}MiB  recommend_vps_ram>={plan.vps_ram_mb}MiB\n"
            )
            for note in plan.notes:
                out.write(f"- {note}\n")
        return 0

    if args.command == "load-test":
        xray_bin = args.xray_bin
        if not Path(xray_bin).exists() and shutil.which(xray_bin):
            xray_bin = shutil.which(xray_bin) or xray_bin
        if not Path(xray_bin).exists():
            raise ConfigError(f"xray binary not found: {args.xray_bin}")
        private, public = keys.generate_keypair()
        with tempfile.TemporaryDirectory(prefix="shahrah-load-") as tmp:
            report = loadtest.run_load(
                xray_bin,
                Path(tmp),
                connections=args.connections,
                target=args.target,
                idle_s=args.idle_s,
                public_key=public,
                private_key=private,
                require_reap=not args.skip_reap,
            )
        if args.json:
            out.write(json.dumps(report.as_dict(), indent=2) + "\n")
        else:
            d = report.as_dict()
            out.write(
                f"ok={d['ok']}/{d['connections']}  rate={d['success_rate']:.4f}  "
                f"p50={d['p50_ms']}ms  p95={d['p95_ms']}ms  "
                f"peak={d['echo_peak']}  reaped={d['idle_reaped']}  "
                f"took={d['duration_s']}s\n"
            )
            if d["errors_sample"]:
                out.write("errors: " + "; ".join(d["errors_sample"]) + "\n")
        # Non-zero when the harness itself could not meet a basic capacity bar.
        if report.ok < args.connections * 0.95:
            return 2
        if not args.skip_reap and not report.idle_reaped:
            return 3
        return 0

    if args.command == "settle-hook":
        if not args.secret:
            raise ConfigError("pass --secret or set SHAHRAH_SETTLE_SECRET")
        if args.emit_curl:
            req = settle.signed_request(
                args.secret,
                {"username": args.emit_curl, "days": args.days, "payment_id": "demo"},
                base_url=f"http://{args.listen}",
            )
            out.write(
                f"curl -sS -X POST {req['url']!r} \\\n"
                f"  -H 'Content-Type: application/json' \\\n"
                f"  -H '{req['header']}: {req['signature']}' \\\n"
                f"  -d {req['body']!r}\n"
            )
            return 0
        if not args.panel_url:
            raise ConfigError("--panel-url (or SHAHRAH_PANEL_URL) is required")
        host, _, port_text = args.listen.partition(":")
        port = int(port_text or "8790")
        client = _panel_client(args.panel_url)

        def credit(username: str, add_expire_s: int, add_bytes: int) -> None:
            settle.credit_user(
                client,
                settle.SettleEvent(username, add_expire_s, add_bytes),
            )

        out.write(f"settle webhook on http://{host or '127.0.0.1'}:{port}/hooks/payment\n")
        settle.serve(args.secret, credit, host=host or "127.0.0.1", port=port)
        return 0

    if args.command == "sni-bank":
        return _sni_bank(args, out)

    if args.command == "sni-scout":
        results = sni_scout.scout(
            args.hosts,
            timeout_s=args.timeout,
            allow_risky=args.allow_risky,
            use_defaults=args.defaults,
            node_ip=args.node_ip,
            strict_dns=args.strict_dns,
        )
        if args.json:
            out.write(
                json.dumps(
                    [
                        {
                            "host": r.host,
                            "ok": r.ok,
                            "latency_ms": r.latency_ms,
                            "tls_version": r.tls_version,
                            "alpn": r.alpn,
                            "detail": r.detail,
                            "architectures": list(r.architectures),
                            "sni_dns": r.dns.as_dict() if r.dns else None,
                        }
                        for r in results
                    ],
                    indent=2,
                )
                + "\n"
            )
        else:
            for result in results:
                mark = "ok " if result.ok else "NO "
                latency = f"{result.latency_ms:.0f}ms" if result.latency_ms is not None else "-"
                arch = ",".join(result.architectures) or "-"
                out.write(
                    f"{mark} {result.host:40} {latency:>8}  "
                    f"{result.tls_version or '-':8}  {result.alpn or '-':8}  "
                    f"{arch:8}  {result.detail}\n"
                )
            ranking = sni_scout.ranking(results)
            out.write(f"ranking: {' '.join(ranking) if ranking else '(none)'}\n")
        return 0 if any(r.ok for r in results) else 1

    state = load_state(state_path)

    if args.command == "rotate-reality":
        old_pub = state.public_key
        state = state.rotate_reality(new_short_id=not args.keep_short_id)
        save_state(state_path, state)
        out.write(
            f"REALITY key rotated\nold public key: {old_pub}\n"
            f"new public key: {state.public_key}\n"
            f"short id: {state.short_ids[0]}\n"
            "next: shahrah apply && systemctl restart shahrah-xray "
            "then re-issue client links / update brain.json\n"
        )
        return 0

    if args.command == "retarget":
        state = state.with_target(args.target)
        save_state(state_path, state)
        out.write(
            f"REALITY target -> {state.target_host}\n"
            "next: shahrah apply && systemctl restart shahrah-xray "
            "and update brain.json / client links (sni=)\n"
        )
        return 0

    if args.command == "access-log":
        if args.off:
            state = state.with_access_log(None)
        else:
            if not args.path:
                raise ConfigError("pass a path or --off")
            state = state.with_access_log(args.path)
        save_state(state_path, state)
        out.write(
            f"access_log -> {state.access_log or 'disabled'}\n"
            "next: shahrah apply && systemctl restart shahrah-xray\n"
        )
        return 0

    if args.command == "stats-api":
        if args.off:
            state = state.with_stats_api(None)
        else:
            port = args.port or 10085
            state = state.with_stats_api(port)
        save_state(state_path, state)
        out.write(
            f"stats_api_port -> {state.stats_api_port or 'disabled'}\n"
            "next: shahrah apply && systemctl restart shahrah-xray\n"
        )
        return 0

    if args.command == "usage":
        server = args.server
        if not server:
            if state.stats_api_port is None:
                raise ConfigError(
                    "stats API is disabled; run `shahrah stats-api` then apply + restart"
                )
            server = f"127.0.0.1:{state.stats_api_port}"
        traffic = accounting.query_stats(xray_bin=args.xray_bin, server=server, reset=args.reset)
        if args.json:
            out.write(
                json.dumps({label: row.as_dict() for label, row in traffic.items()}, indent=2)
                + "\n"
            )
        else:
            out.write(accounting.format_table(traffic))
        return 0

    if args.command == "serve-sub":
        if not args.path_secret:
            raise ConfigError("pass --path-secret or set SHAHRAH_SUB_SECRET")
        host, _, port_text = args.listen.partition(":")
        port = int(port_text or "8788")
        # Prefer env so `ps` does not show the path secret on the command line.
        secret = os.environ.get("SHAHRAH_SUB_SECRET", "").strip() or args.path_secret
        labels = [u.label for u in state.users]
        for label in labels:
            out.write(subserve.subscription_url(host or "127.0.0.1", port, secret, label) + "\n")
        out.write("(serving; Ctrl-C to stop)\n")
        subserve.serve(
            state_path,
            secret,
            host=host or "127.0.0.1",
            port=port,
            tactics_path=args.tactics,
        )
        return 0

    if args.command == "node-check":
        ports = [item.port for item in state.server_settings().listeners()]
        if state.hysteria2 is not None:
            ports.append(state.hysteria2.port)
        checks = nodecheck.run_all(
            reality_host=None if args.no_target else state.target_host,
            public_ports=ports,
            cert_pem=args.cert.read_text(encoding="utf-8") if args.cert else None,
            pin=args.pin or (state.hysteria2.pin_sha256 if state.hysteria2 else ""),
        )
        failed = any(c.status == "fail" for c in checks)
        if args.json:
            out.write(json.dumps([c.as_dict() for c in checks], indent=2) + "\n")
        else:
            out.write(f"node-check {'FAIL' if failed else 'PASS'}\n")
            for c in checks:
                out.write(f"  {c.status:4} {c.name}  {c.detail}\n")
        return 2 if failed else 0

    if args.command == "hysteria2":
        return _run_hysteria2(args, state_path, state, out)
    if args.command == "warp":
        return _run_warp(args, state_path, state, out)

    if args.command == "tuning-profile":
        if args.name:
            state = state.with_tuning_profile(args.name)
            save_state(state_path, state)
        out.write(f"tuning_profile -> {state.tuning_profile} (run `shahrah apply` to render)\n")
        return 0

    if args.command == "apply":
        if not state.users:
            raise ConfigError("no users yet: run `shahrah user add <label>` first")
        text = dumps(render_server_config(state.server_settings(), list(state.users), warp=state.warp))
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

    if args.command == "listener":
        if args.listener_command == "add":
            state = state.with_listener(_parse_listener(args.spec))
            save_state(state_path, state)
        elif args.listener_command == "remove":
            state = state.without_listener(args.port)
            save_state(state_path, state)
        for item in state.server_settings().listeners():
            out.write(f"{item.port} {item.profile}\n")
        return 0

    user_obj = state.find_user(args.label)
    endpoints = state.endpoints(args.name)
    if args.command == "link":
        for endpoint in sorted(endpoints, key=lambda e: e.priority):
            out.write(vless_link(endpoint, user_obj) + "\n")
        for extra in state.hysteria2_links(user_obj, args.name):
            out.write(extra + "\n")
    elif args.command == "sub":
        extra_links = state.hysteria2_links(user_obj, args.name)
        out.write(build_subscription(endpoints, user_obj, extra_links=extra_links) + "\n")
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


def _sni_bank(args: argparse.Namespace, out: TextIO) -> int:
    """``shahrah sni-bank``: hostnames and scores only, never secrets."""
    from . import sni_dns

    path = args.bank or Path(args.state).with_name("sni-bank.json")
    ttl = args.ttl_hours * 3600
    now = time.time()
    bank = sni_bank.load_bank(path)
    cmd = args.bank_command
    if cmd in {"seed", "add"}:
        if args.node_ip:
            sni_dns.check("example.invalid", args.node_ip, lambda _n: [])  # validates the IP
            bank = dataclasses.replace(bank, node_ip=args.node_ip)
        if cmd == "seed":
            for region, hosts in sni_bank.SEED_CANDIDATES.items():
                bank = bank.add(hosts, region, now)
        else:
            bank = bank.add(args.hosts, args.region, now)
        sni_bank.save_bank(path, bank)
        out.write(f"{len(bank.candidates)} candidates in {path}\n")
        return 0
    if cmd == "refresh":
        bank = sni_bank.refresh(
            bank,
            now,
            only_due=not args.all,
            ttl_s=ttl,
            timeout_s=args.timeout,
            resolver=sni_dns.system_resolver,
        )
        sni_bank.save_bank(path, bank)
        cmd, args.region, args.strict_dns, args.json = "list", None, False, False
    if cmd == "list":
        scores = bank.ranked(now, region=args.region, ttl_s=ttl, strict_dns=args.strict_dns)
        if args.json:
            rows = [
                {
                    "host": s.host,
                    "region": bank.get(s.host).region,
                    "score": s.total,  # type: ignore[union-attr]
                    "usable": s.usable,
                    "expired": s.expired,
                    "factors": dict(s.factors),
                    "reasons": list(s.reasons),
                }
                for s in scores
            ]
            out.write(json.dumps(rows, indent=2) + "\n")
        else:
            for s in scores:
                flag = "ok " if s.usable else ("EXP" if s.expired else "NO ")
                region = bank.get(s.host).region  # type: ignore[union-attr]
                out.write(
                    f"{flag} {s.total:5.1f}  {region:7}  {s.host:36}  {'; '.join(s.reasons)}\n"
                )
        return 0 if any(s.usable for s in scores) else 1
    if cmd == "rotate":
        rot = sni_bank.rotation(bank, args.region, now, ttl_s=ttl)
        out.write(
            f"{args.region}: current={rot.current or '-'} pick={rot.pick or '-'} "
            f"rotate={'yes' if rot.rotate else 'no'} ({rot.reason})\n"
        )
        if rot.rotate and rot.pick and args.apply:
            sni_bank.save_bank(path, sni_bank.activate(bank, args.region, rot.pick))
            out.write(
                f"active {args.region} SNI -> {rot.pick}; next: shahrah retarget {rot.pick}\n"
            )
        return 0 if rot.pick else 1
    if cmd == "report":
        results = [sni_scout._handshake(c.host, 443, args.timeout) for c in bank.candidates]
        report = sni_bank.build_vantage_report(results, vantage=args.vantage, asn=args.asn, now=now)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        out.write(f"wrote {len(results)} results to {args.out}\n")
        return 0
    if cmd == "merge":
        for rep in args.reports:
            bank = sni_bank.merge_vantage_report(bank, json.loads(rep.read_text()), now=now)
        sni_bank.save_bank(path, bank)
        out.write(f"merged {len(args.reports)} report(s)\n")
        return 0
    raise ConfigError(f"unknown sni-bank command {cmd!r}")
