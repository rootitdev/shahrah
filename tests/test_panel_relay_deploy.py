from __future__ import annotations

import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BETA = REPO / "deploy" / "beta"


def test_panel_exit_attach_bash_syntax() -> None:
    script = BETA / "panel-exit-attach-waterwall.sh"
    subprocess.run(["bash", "-n", str(script)], check=True, cwd=REPO)


def test_panel_exit_attach_does_not_require_state_json() -> None:
    text = (BETA / "panel-exit-attach-waterwall.sh").read_text(encoding="utf-8")
    assert 'die "missing' not in text
    assert "127.0.0.1:443" in text
    assert "PANEL_OWNED=1" in text


def test_germany_attach_panel_branch_in_script() -> None:
    text = (BETA / "germany-attach-waterwall.sh").read_text(encoding="utf-8")
    assert "PANEL_OWNED" in text
    assert "panel-exit-attach-waterwall.sh" in text


def test_relay_install_script_documents_wheelhouse() -> None:
    text = (BETA / "iran-relay-install.sh").read_text(encoding="utf-8")
    assert "SHAHRAH_WHEELHOUSE" in text
