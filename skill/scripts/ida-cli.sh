#!/usr/bin/env bash
set -euo pipefail

REPO="${IDA_CLI_REPO:-cpkt9762/ida-cli}"
INSTALL_REF="${IDA_CLI_INSTALL_REF:-master}"
INSTALL_URL="https://raw.githubusercontent.com/${REPO}/${INSTALL_REF}/scripts/install.sh"
DEFAULT_BIN="${IDA_CLI_BIN:-$HOME/.local/bin/ida-cli}"
INSTALL_ARGS="${IDA_CLI_INSTALL_ARGS:-}"

find_ida_cli() {
  if command -v ida-cli >/dev/null 2>&1; then
    command -v ida-cli
    return 0
  fi

  if [[ -x "$DEFAULT_BIN" ]]; then
    printf '%s\n' "$DEFAULT_BIN"
    return 0
  fi

  return 1
}

install_ida_cli() {
  echo "[ida skill] installing ida-cli from ${REPO}@${INSTALL_REF}" >&2
  if [[ -n "$INSTALL_ARGS" ]]; then
    curl -fsSL "$INSTALL_URL" | bash -s -- $INSTALL_ARGS
  else
    curl -fsSL "$INSTALL_URL" | bash
  fi
}

IDA_CLI_BIN_PATH="$(find_ida_cli || true)"
if [[ -z "$IDA_CLI_BIN_PATH" ]]; then
  install_ida_cli
  IDA_CLI_BIN_PATH="$(find_ida_cli || true)"
fi

if [[ -z "$IDA_CLI_BIN_PATH" ]]; then
  echo "[ida skill] ida-cli install finished but binary was not found on PATH or at ${DEFAULT_BIN}" >&2
  exit 1
fi

if ! "$IDA_CLI_BIN_PATH" --help >/dev/null 2>&1; then
  cat >&2 <<EOF
[ida skill] ida-cli exists at ${IDA_CLI_BIN_PATH} but failed a smoke test.
If this machine has multiple IDA versions installed, export IDADIR explicitly and retry.
Example:
  export IDADIR="/Applications/IDA Professional 9.4.app/Contents/MacOS"
  ${IDA_CLI_BIN_PATH} probe-runtime
EOF
  exit 1
fi

exec "$IDA_CLI_BIN_PATH" "$@"
