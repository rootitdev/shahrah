from __future__ import annotations

import json
import subprocess
from pathlib import Path

from shahrah.models import Profile
from shahrah.state import NodeState


def test_backup_and_restore_drill_never_touches_live(tmp_path: Path) -> None:
    conf = tmp_path / "conf"
    conf.mkdir()
    live = NodeState.create(
        public_host="exit.example.com",
        target_host="www.example.com",
        profile=Profile.REALITY_VISION,
    )
    state_path = conf / "state.json"
    state_path.write_text(live.to_json(), encoding="utf-8")
    (conf / "xray.json").write_text(
        '{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[]}',
        encoding="utf-8",
    )

    dest = tmp_path / "backups"
    pass_file = tmp_path / "backup.pass"
    env = {
        **dict(subprocess.os.environ),
        "CONF_DIR": str(conf),
        "BACKUP_DEST": str(dest),
        "BACKUP_PASS_FILE": str(pass_file),
    }
    root = Path(__file__).resolve().parents[1]
    subprocess.run(
        ["bash", str(root / "scripts/backup-shahrah-bundle.sh")],
        check=True,
        env=env,
        cwd=root,
    )
    archives = list(dest.glob("shahrah-bundle-*.tar.gz.gpg"))
    assert len(archives) == 1

    drill_env = {
        **env,
        "LIVE_STATE": str(state_path),
        "DRILL_ROOT": str(tmp_path / "drill"),
    }
    subprocess.run(
        ["bash", str(root / "scripts/restore-shahrah-drill.sh"), str(archives[0])],
        check=True,
        env=drill_env,
        cwd=root,
    )
    drill_state = (tmp_path / "drill" / "state.json").read_text(encoding="utf-8")
    assert json.loads(drill_state)["public_host"] == "exit.example.com"
    assert json.loads(state_path.read_text()) == json.loads(drill_state)
