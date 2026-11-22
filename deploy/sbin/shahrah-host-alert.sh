#!/usr/bin/env bash
# Local host health → Telegram on state *change* (RAM/CPU/service down).
set -euo pipefail

ENV_FILE="${HOST_ALERT_ENV:-/etc/shahrah/host-alert.env}"
SECRETS="${HOST_ALERT_SECRETS:-/root/.vpn-secrets/.env}"
STATE="${HOST_ALERT_STATE:-/var/lib/shahrah/host-alert.state}"
LOCK="${HOST_ALERT_LOCK:-/run/shahrah-host-alert.lock}"

mkdir -p "$(dirname "$STATE")"
exec 9>"$LOCK"
flock -n 9 || exit 0

[[ -f "$ENV_FILE" ]] && set -a && # shellcheck source=/dev/null
  source "$ENV_FILE" && set +a
if [[ -f "$SECRETS" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$SECRETS"
  set +a
fi

HOST_LABEL="${HOST_LABEL:-$(hostname -s)}"
ROLE="${HOST_ROLE:-unknown}"
MEM_WARN_PCT="${MEM_WARN_PCT:-88}"
MEM_CRIT_PCT="${MEM_CRIT_PCT:-95}"
CPU_LOAD_MULT="${CPU_LOAD_MULT:-2.0}"
SERVICES="${SERVICES:-}"
DOCKER_NAMES="${DOCKER_NAMES:-}"
CHECK_PORT_8000="${CHECK_PORT_8000:-0}"
REPEAT_CRIT_MIN="${REPEAT_CRIT_MIN:-45}"

if [[ -z "${TELEGRAM_BOT_TOKEN:-}" || -z "${TELEGRAM_CHAT_ID:-}" ]]; then
  echo "[host-alert] missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID" >&2
  exit 0
fi

tg_send() {
  local text=$1
  printf '%s' "$text" | python3 -c '
import os, sys, urllib.parse, urllib.request
text = sys.stdin.read()
data = urllib.parse.urlencode({
    "chat_id": os.environ["TELEGRAM_CHAT_ID"],
    "text": text,
    "disable_web_page_preview": "1",
}).encode()
url = "https://api.telegram.org/bot" + os.environ["TELEGRAM_BOT_TOKEN"] + "/sendMessage"
urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=25)
' 2>/dev/null || true
}

mem_pct() {
  python3 <<'PY'
import pathlib
info = {}
for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
    k, _, v = line.partition(":")
    if v:
        info[k.strip()] = int(v.split()[0])
total = info.get("MemTotal", 1)
avail = info.get("MemAvailable", 0)
used_pct = int(round((total - avail) * 100.0 / total))
print(used_pct, avail // 1024, total // 1024)
PY
}

cpu_high() {
  python3 <<PY
import os
load1 = float(open("/proc/loadavg").read().split()[0])
ncpu = os.cpu_count() or 1
mult = float("${CPU_LOAD_MULT}")
print(1 if load1 > ncpu * mult else 0)
PY
}

service_down() {
  local down=()
  local u
  for u in $SERVICES; do
    [[ -n "$u" ]] || continue
    if ! systemctl is-active --quiet "$u" 2>/dev/null; then
      down+=("$u")
    fi
  done
  local d
  for d in $DOCKER_NAMES; do
    [[ -n "$d" ]] || continue
    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$d"; then
      down+=("docker:$d")
    fi
  done
  if [[ "$CHECK_PORT_8000" == "1" ]]; then
    if ! ss -ltn 2>/dev/null | grep -q ':8000 '; then
      down+=("port:8000")
    fi
  fi
  (IFS=,; echo "${down[*]-}")
}

read -r mem_used avail_mb total_mb <<<"$(mem_pct)"
cpu_flag=$(cpu_high)
down_list=$(service_down)
load=$(awk '{print $1,$2,$3}' /proc/loadavg)
ncpu=$(nproc)

mem_high=0
mem_crit=0
[[ "$mem_used" -ge "$MEM_WARN_PCT" ]] && mem_high=1
[[ "$mem_used" -ge "$MEM_CRIT_PCT" ]] && mem_crit=1

# Coarse severity only — do NOT put exact RAM% in the key (that spammed Telegram).
if [[ -n "$down_list" ]]; then
  level=down
  status="🔴 سرویس خاموش"
elif [[ "$mem_crit" -eq 1 ]]; then
  level=crit
  status="🔴 RAM بحرانی"
elif [[ "$mem_high" -eq 1 ]]; then
  level=warn
  status="🟠 RAM بالا"
elif [[ "$cpu_flag" == 1 ]]; then
  level=warn
  status="🟠 CPU/Load بالا"
else
  level=ok
  status="🟢 مشکل برطرف شد"
fi

key="${HOST_LABEL}|${ROLE}|${level}|down=${down_list}"
prev=""
[[ -f "$STATE" ]] && prev=$(cat "$STATE" 2>/dev/null || true)
now_ts=$(date +%s)
last_crit=0
[[ -f "${STATE}.crit" ]] && last_crit=$(cat "${STATE}.crit" 2>/dev/null || echo 0)

# First run: seed state quietly (no "همه چیز OK" spam after install).
if [[ ! -f "$STATE" ]]; then
  printf '%s\n' "$key" >"$STATE"
  exit 0
fi

should_send=0
if [[ "$key" != "$prev" ]]; then
  # Only notify when something is bad, or when recovering from bad → ok.
  if [[ "$level" != "ok" ]]; then
    should_send=1
  else
    prev_level=$(printf '%s' "$prev" | cut -d'|' -f3)
    if [[ "$prev_level" != "ok" && -n "$prev_level" ]]; then
      should_send=1
    fi
  fi
fi
# Re-ping critical / down every REPEAT_CRIT_MIN (not healthy).
if [[ "$level" == "crit" || "$level" == "down" ]]; then
  if (( now_ts - last_crit >= REPEAT_CRIT_MIN * 60 )); then
    should_send=1
  fi
fi

printf '%s\n' "$key" >"$STATE"

if [[ "$should_send" -eq 0 ]]; then
  exit 0
fi

down_msg=""
if [[ -n "$down_list" ]]; then
  down_msg="
down: ${down_list}"
fi

if swapon --show 2>/dev/null | grep -q .; then
  swap_line=$(swapon --show --bytes | awk 'NR==2{printf "Swap: %.0f/%.0f MiB used", $4/1024/1024, $3/1024/1024}')
else
  swap_line="Swap: off"
fi

msg="${status}
${HOST_LABEL} (${ROLE})
RAM: ${mem_used}% (${avail_mb}MB free / ${total_mb}MB)
Load: ${load} (${ncpu} CPU)
${swap_line}${down_msg}"

tg_send "$msg"
if [[ "$level" == "crit" || "$level" == "down" ]]; then
  echo "$now_ts" >"${STATE}.crit"
fi