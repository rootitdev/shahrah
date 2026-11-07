# Shared CLI bootstrap for deploy scripts. Source after setting SHAHRAH_SRC_DIR (repo root).
# Ensures commands from the checkout run before a stale /usr/local/bin/shahrah.
: "${SHAHRAH_SRC_DIR:?set SHAHRAH_SRC_DIR to the shahrah git root}"
: "${SHAHRAH_APP_DIR:=/opt/shahrah}"
: "${SHAHRAH_PYTHON:=python3}"

shahrah_cli_version() {
  "$1" lifecycle version --json 2>/dev/null || echo '{}'
}

shahrah_cli_has_feature() {
  local bin="$1" feat="$2"
  "$bin" lifecycle has-feature --name "$feat" >/dev/null 2>&1
}

bootstrap_shahrah_cli() {
  local venv="$SHAHRAH_APP_DIR/venv" pip_log
  install -d -m 0755 "$SHAHRAH_APP_DIR"
  if ! "$SHAHRAH_PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info>=(3,11) else 1)' 2>/dev/null; then
    SHAHRAH_PYTHON="python3.11"
  fi
  if [[ ! -x "$venv/bin/python" ]]; then
    "$SHAHRAH_PYTHON" -m venv "$venv"
  fi
  pip_log="$(mktemp)"
  if ! "$venv/bin/pip" install -q --upgrade "$SHAHRAH_SRC_DIR" >"$pip_log" 2>&1; then
    printf 'error: نصب بسته از سورس شکست خورد (credentialها دست‌نخورده).\n' >&2
    tail -n 5 "$pip_log" >&2
    rm -f "$pip_log"
    return 1
  fi
  rm -f "$pip_log"
  export SHAHRAH_CLI="$venv/bin/shahrah"
  export PATH="$venv/bin:$PATH"
  if ! shahrah_cli_has_feature "$SHAHRAH_CLI" lifecycle; then
    printf 'error: CLI سورس ناسازگار است — SHAHRAH_SRC_DIR را بررسی کنید.\n' >&2
    return 1
  fi
  return 0
}

# Prefer bootstrapped venv; else system CLI if feature exists; else bootstrap attempt.
resolve_shahrah_cli() {
  if [[ -n "${SHAHRAH_CLI:-}" && -x "$SHAHRAH_CLI" ]]; then
    return 0
  fi
  if [[ -x "$SHAHRAH_APP_DIR/venv/bin/shahrah" ]] \
    && shahrah_cli_has_feature "$SHAHRAH_APP_DIR/venv/bin/shahrah" lifecycle; then
    export SHAHRAH_CLI="$SHAHRAH_APP_DIR/venv/bin/shahrah"
    export PATH="$SHAHRAH_APP_DIR/venv/bin:$PATH"
    return 0
  fi
  if command -v shahrah >/dev/null \
    && shahrah_cli_has_feature "$(command -v shahrah)" lifecycle; then
    export SHAHRAH_CLI="$(command -v shahrah)"
    return 0
  fi
  bootstrap_shahrah_cli
}

shahrah_cli() {
  resolve_shahrah_cli || return 1
  "$SHAHRAH_CLI" "$@"
}

shahrah_cli_or_die() {
  resolve_shahrah_cli || {
    cat >&2 <<'EOF'
خطا: نسخهٔ نصب‌شدهٔ shahrah با این سورس هم‌خوان نیست.
قدم بعدی: cd /opt/shahrah && sudo ./deploy/install.sh --host ... --target ...
(سورس را به‌روز کرده‌اید؛ یک بار install از همان درخت سورس CLI را هم به‌روز می‌کند.)
EOF
    exit 2
  }
  "$SHAHRAH_CLI" "$@"
}
