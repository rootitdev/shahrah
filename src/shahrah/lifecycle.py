"""Install/runtime lifecycle status for operators (Persian-friendly summaries)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .models import ConfigError

LIFECYCLE_API = 2
KNOWN_FEATURES = frozenset(
    {
        "lifecycle",
        "record-provenance",
        "uninstall-plan",
        "reconfigure",
        "relay",
        "waterwall-binary",
    }
)

STATE_PATH = Path("/etc/shahrah/state.json")
APP_VENV = Path("/opt/shahrah/venv/bin/shahrah")
SRC_MARK = Path("/opt/shahrah/.git")


@dataclass(slots=True)
class LifecycleReport:
    install_state: str  # NOT_INSTALLED | INSTALLED | INCOMPLETE | STOPPED | UNHEALTHY
    source_revision: str
    installed_cli_revision: str
    cli_mismatch: bool
    role: str
    services: dict[str, str]
    listeners: list[int]
    config_valid: bool | None
    config_detail: str
    next_steps: list[str] = field(default_factory=list)
    messages_fa: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, ensure_ascii=False) + "\n"


def _git_revision(root: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _pip_revision() -> str:
    try:
        out = subprocess.run(
            [sys.executable, "-m", "pip", "show", "shahrah"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if out.returncode != 0:
            return "not-installed"
        m = re.search(r"^Version:\s*(.+)$", out.stdout, re.MULTILINE)
        return (m.group(1).strip() if m else "unknown") + " (pip)"
    except OSError:
        return "unknown"


def _systemd_state(unit: str) -> str:
    try:
        out = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True,
            text=True,
            timeout=5,
        )
        text = out.stdout.strip()
        if text in ("active", "inactive", "failed", "activating"):
            return text
        return "unknown"
    except OSError:
        return "n/a"


def has_feature(feature: str) -> bool:
    return feature in KNOWN_FEATURES


def build_report(*, src_root: Path | None = None, run_xray_test: bool = False) -> LifecycleReport:
    root = src_root or Path(os.environ.get("SHAHRAH_SRC_DIR", "/opt/shahrah"))
    if not root.is_dir():
        root = Path("/opt/shahrah")

    src_rev = _git_revision(root) if (root / ".git").is_dir() else "unknown"
    pip_rev = _pip_revision()
    cli_mismatch = False
    if APP_VENV.is_file() and src_rev != "unknown":
        # Mismatch hint when system shahrah exists but venv missing features (checked elsewhere)
        cli_mismatch = not APP_VENV.is_file() and Path("/usr/local/bin/shahrah").is_file()

    state_exists = STATE_PATH.is_file()
    install_state = "NOT_INSTALLED"
    listeners: list[int] = []
    role = "unknown"
    config_valid: bool | None = None
    config_detail = ""
    services: dict[str, str] = {}
    next_steps: list[str] = []
    messages_fa: list[str] = []

    if state_exists:
        install_state = "INSTALLED"
        try:
            from .state import load_state

            state = load_state(STATE_PATH)
            role = "node"
            listeners = [item.port for item in state.server_settings().listeners()]
            messages_fa.append("پیکربندی نود: state.json موجود است (کلیدها حفظ شده‌اند).")
        except ConfigError as exc:
            install_state = "INCOMPLETE"
            config_detail = str(exc)
            messages_fa.append("پیکربندی نود: state.json ناقص یا خراب است.")
            next_steps.append("بررسی /etc/shahrah/state.json یا بازیابی از snapshot")
    else:
        messages_fa.append("هنوز نود شاهراه نصب نشده (state.json نیست).")
        next_steps.append("sudo ./deploy/install.sh --host HOST --target www.cloudflare.com")

    for unit in ("shahrah-xray", "shahrah-waterwall", "shahrah-brain"):
        services[unit] = _systemd_state(unit)

    if services.get("shahrah-xray") == "active":
        messages_fa.append("سرویس shahrah-xray: فعال (پردازش در حال اجراست).")
    elif state_exists:
        install_state = "STOPPED" if install_state == "INSTALLED" else install_state
        messages_fa.append("سرویس shahrah-xray: متوقف — ترافیک از این میزبان عبور نمی‌کند.")

    if run_xray_test and state_exists and Path("/etc/shahrah/xray.json").is_file():
        xray = os.environ.get("SHAHRAH_XRAY_BIN", "/usr/local/bin/xray")
        if Path(xray).is_file():
            proc = subprocess.run(
                [xray, "run", "-test", "-config", "/etc/shahrah/xray.json"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            config_valid = proc.returncode == 0
            if not config_valid:
                install_state = "UNHEALTHY"
                config_detail = (proc.stderr or proc.stdout or "xray -test failed")[:200]
                messages_fa.append("اعتبارسنجی xray.json: ناموفق — سرویس ممکن است بالا نیاید.")
                next_steps.append(
                    "sudo shahrah --state /etc/shahrah/state.json apply --xray-bin /usr/local/bin/xray "
                    "--config-out /etc/shahrah/xray.json --group shahrah && systemctl restart shahrah-xray"
                )
            else:
                messages_fa.append("اعتبارسنجی xray.json: موفق (فقط پیکربندی؛ نه تست اینترنت).")
        else:
            config_valid = None
            messages_fa.append("باینری xray یافت نشد — فقط وضعیت فایل‌ها گزارش شد.")

    if src_rev != "unknown" and pip_rev.startswith("not"):
        cli_mismatch = True
        messages_fa.append("CLI پایتون از pip نصب نشده — احتمال ناسازگاری با سورس git.")
        next_steps.insert(0, "cd /opt/shahrah && sudo ./deploy/install.sh --host ... --target ...")

    return LifecycleReport(
        install_state=install_state,
        source_revision=src_rev,
        installed_cli_revision=pip_rev,
        cli_mismatch=cli_mismatch,
        role=role,
        services=services,
        listeners=listeners,
        config_valid=config_valid,
        config_detail=config_detail,
        next_steps=next_steps,
        messages_fa=messages_fa,
    )
