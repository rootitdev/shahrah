# Shared CLI bootstrap for deploy scripts. Source after setting SHAHRAH_SRC_DIR (repo root).
: "${SHAHRAH_SRC_DIR:?set SHAHRAH_SRC_DIR to the shahrah git root}"
: "${SHAHRAH_APP_DIR:=/opt/shahrah}"
: "${SHAHRAH_PYTHON:=python3}"

export SHAHRAH_CLI_MODE=""

shahrah_cli_has_feature() {
  local bin="$1" feat="$2"
  "$bin" lifecycle has-feature --name "$feat" >/dev/null 2>&1
}

shahrah_cli_has_feature_module() {
  local feat="$1"
  PYTHONPATH="${SHAHRAH_SRC_DIR}/src${PYTHONPATH:+:$PYTHONPATH}" \
    "$SHAHRAH_PYTHON" -m shahrah lifecycle has-feature --name "$feat" >/dev/null 2>&1
}

_run_shahrah_cli() {
  if [[ "${SHAHRAH_CLI_MODE:-}" == module ]]; then
    PYTHONPATH="${SHAHRAH_SRC_DIR}/src${PYTHONPATH:+:$PYTHONPATH}" \
      "$SHAHRAH_PYTHON" -m shahrah "$@"
  else
    "$SHAHRAH_CLI" "$@"
  fi
}

# Read-only: existing venv, system CLI, or python -m from SRC — never pip/venv writes.
resolve_shahrah_cli_readonly() {
  if [[ -n "${SHAHRAH_CLI:-}" && -x "$SHAHRAH_CLI" && "${SHAHRAH_CLI_MODE:-}" != module ]]; then
    if shahrah_cli_has_feature "$SHAHRAH_CLI" lifecycle; then
      return 0
    fi
  fi
  if [[ -x "$SHAHRAH_APP_DIR/venv/bin/shahrah" ]] \
    && shahrah_cli_has_feature "$SHAHRAH_APP_DIR/venv/bin/shahrah" lifecycle; then
    export SHAHRAH_CLI="$SHAHRAH_APP_DIR/venv/bin/shahrah"
    export SHAHRAH_CLI_MODE=""
    return 0
  fi
  if command -v shahrah >/dev/null; then
    local sys
    sys="$(command -v shahrah)"
    if shahrah_cli_has_feature "$sys" lifecycle; then
      export SHAHRAH_CLI="$sys"
      export SHAHRAH_CLI_MODE=""
      return 0
    fi
  fi
  if [[ -f "$SHAHRAH_SRC_DIR/src/shahrah/__main__.py" ]] \
    && shahrah_cli_has_feature_module lifecycle; then
    export SHAHRAH_CLI="$SHAHRAH_PYTHON"
    export SHAHRAH_CLI_MODE=module
    return 0
  fi
  return 1
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
  local pip_install=(install -q --upgrade "$SHAHRAH_SRC_DIR")
  if [[ -n "${SHAHRAH_WHEELHOUSE:-}" ]]; then
    pip_install=(install -q --no-index --find-links "$SHAHRAH_WHEELHOUSE" "$SHAHRAH_SRC_DIR")
  fi
  if ! "$venv/bin/pip" "${pip_install[@]}" >"$pip_log" 2>&1; then
    printf 'error: نصب بسته از سورس شکست خورد (credentialها دست‌نخورده).\n' >&2
    tail -n 5 "$pip_log" >&2
    rm -f "$pip_log"
    return 1
  fi
  rm -f "$pip_log"
  export SHAHRAH_CLI="$venv/bin/shahrah"
  export SHAHRAH_CLI_MODE=""
  export PATH="$venv/bin:$PATH"
  if ! shahrah_cli_has_feature "$SHAHRAH_CLI" lifecycle; then
    printf 'error: CLI سورس ناسازگار است.\n' >&2
    return 1
  fi
  return 0
}

# Mutating installs only: readonly resolve, then bootstrap with consent (install.sh).
resolve_shahrah_cli() {
  if resolve_shahrah_cli_readonly; then
    return 0
  fi
  bootstrap_shahrah_cli
}

shahrah_cli_readonly() {
  if ! resolve_shahrah_cli_readonly; then
    return 1
  fi
  _run_shahrah_cli "$@"
}

shahrah_cli() {
  resolve_shahrah_cli || return 1
  _run_shahrah_cli "$@"
}

shahrah_cli_or_die() {
  local readonly="${SHAHRAH_CLI_READONLY:-0}"
  if [[ "$readonly" == 1 ]]; then
    if ! shahrah_cli_readonly "$@"; then
      cat >&2 <<'EOF'
خطا: CLI نصب‌شده با سورس هم‌خوان نیست (پیش‌نمایش فقط-خواندنی).
قدم bootstrap: sudo ./deploy/install.sh --host ... --target ...
EOF
      exit 2
    fi
    return 0
  fi
  resolve_shahrah_cli || {
    cat >&2 <<'EOF'
خطا: نسخهٔ نصب‌شدهٔ shahrah با این سورس هم‌خوان نیست.
قدم bootstrap: sudo ./deploy/install.sh --host ... --target ...
EOF
    exit 2
  }
  _run_shahrah_cli "$@"
}
