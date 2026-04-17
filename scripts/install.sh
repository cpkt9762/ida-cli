#!/usr/bin/env bash
set -euo pipefail

REPO="${IDA_CLI_REPO:-gmh5225/ida-cli}"
DEFAULT_REF="${IDA_CLI_DEFAULT_REF:-master}"
BIN_DIR="${IDA_CLI_BIN_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}"
INSTALL_ROOT="${IDA_CLI_INSTALL_ROOT:-${XDG_DATA_HOME:-$HOME/.local/share}/ida-cli}"

TAG=""
REF=""
ADD_PATH=0
BUILD_FROM_SOURCE=0
KEEP_TEMP=0

usage() {
  cat <<'EOF'
Install ida-cli from GitHub releases or build it locally from source.

Usage:
  install.sh [options]

Options:
  --tag <tag>            Install a specific release tag, for example v0.9.3
  --ref <ref>            Build from a git ref or branch, for example master or patch-1
  --bin-dir <dir>        Install the launcher into this directory
  --install-root <dir>   Store downloaded or built files under this directory
  --add-path             Append the bin directory to the active shell rc file
  --build-from-source    Skip release assets and build from source locally
  --keep-temp            Keep the temporary working directory
  --help                 Show this message

Examples:
  curl -fsSL https://raw.githubusercontent.com/gmh5225/ida-cli/master/scripts/install.sh | bash
  curl -fsSL https://raw.githubusercontent.com/gmh5225/ida-cli/master/scripts/install.sh | bash -s -- --add-path
  curl -fsSL https://raw.githubusercontent.com/gmh5225/ida-cli/master/scripts/install.sh | bash -s -- --tag v0.9.3
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      TAG="${2:-}"
      shift 2
      ;;
    --ref)
      REF="${2:-}"
      shift 2
      ;;
    --bin-dir)
      BIN_DIR="${2:-}"
      shift 2
      ;;
    --install-root)
      INSTALL_ROOT="${2:-}"
      shift 2
      ;;
    --add-path)
      ADD_PATH=1
      shift
      ;;
    --build-from-source)
      BUILD_FROM_SOURCE=1
      shift
      ;;
    --keep-temp)
      KEEP_TEMP=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need_cmd curl
need_cmd tar
need_cmd mktemp

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    PLATFORM="Darwin"
    ARCHIVE_EXT="tar.gz"
    LIB_ENV="DYLD_LIBRARY_PATH"
    ;;
  Linux)
    PLATFORM="Linux"
    ARCHIVE_EXT="tar.gz"
    LIB_ENV="LD_LIBRARY_PATH"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    PLATFORM="Windows"
    ARCHIVE_EXT="zip"
    LIB_ENV="PATH"
    ;;
  *)
    echo "unsupported operating system: $OS" >&2
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64|amd64)
    ARCH_LABEL="x86_64"
    ;;
  arm64|aarch64)
    ARCH_LABEL="arm64"
    ;;
  *)
    echo "unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

if [[ "$PLATFORM" == "Windows" && "$ARCH_LABEL" != "x86_64" ]]; then
  echo "prebuilt Windows assets currently support x86_64 only" >&2
  exit 1
fi

if [[ "$PLATFORM" == "Windows" ]]; then
  ASSET_NAME="ida-cli-Windows_x86_64.zip"
  BINARY_NAME="ida-cli.exe"
else
  ASSET_NAME="ida-cli-${PLATFORM}_${ARCH_LABEL}.${ARCHIVE_EXT}"
  BINARY_NAME="ida-cli"
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
  if [[ "$KEEP_TEMP" -eq 0 ]]; then
    rm -rf "$TMP_DIR"
  else
    echo "kept temporary directory: $TMP_DIR"
  fi
}
trap cleanup EXIT

mkdir -p "$BIN_DIR" "$INSTALL_ROOT"
REAL_BIN="$INSTALL_ROOT/ida-cli.real"
LAUNCHER="$BIN_DIR/ida-cli"

download_release_asset() {
  local base_url
  if [[ -n "$TAG" ]]; then
    base_url="https://github.com/${REPO}/releases/download/${TAG}"
  else
    base_url="https://github.com/${REPO}/releases/latest/download"
  fi

  local archive_path="$TMP_DIR/$ASSET_NAME"
  echo "downloading release asset: ${ASSET_NAME}"
  curl -fsSL "${base_url}/${ASSET_NAME}" -o "$archive_path"

  case "$ARCHIVE_EXT" in
    tar.gz)
      tar -xzf "$archive_path" -C "$TMP_DIR"
      ;;
    zip)
      need_cmd unzip
      unzip -q "$archive_path" -d "$TMP_DIR"
      ;;
  esac

  local extracted
  extracted="$(find "$TMP_DIR" -type f \( -name "ida-cli" -o -name "ida-cli.exe" \) | head -n 1)"
  if [[ -z "$extracted" ]]; then
    echo "release asset did not contain ${BINARY_NAME}" >&2
    return 1
  fi

  cp "$extracted" "$REAL_BIN"
  chmod +x "$REAL_BIN"
}

ensure_sdk_for_source_build() {
  if [[ -n "${IDASDKDIR:-}" || -n "${IDALIB_SDK:-}" ]]; then
    return 0
  fi

  need_cmd git
  local sdk_dir="$TMP_DIR/ida-sdk"
  echo "cloning open-source IDA SDK into ${sdk_dir}"
  git clone --depth 1 https://github.com/HexRaysSA/ida-sdk.git "$sdk_dir" >/dev/null 2>&1
  export IDASDKDIR="$sdk_dir"
}

build_from_source() {
  need_cmd cargo

  local source_url
  if [[ -n "$TAG" ]]; then
    source_url="https://github.com/${REPO}/archive/refs/tags/${TAG}.tar.gz"
  else
    source_url="https://github.com/${REPO}/archive/refs/heads/${REF:-$DEFAULT_REF}.tar.gz"
  fi

  local source_archive="$TMP_DIR/source.tar.gz"
  echo "downloading source archive"
  curl -fsSL "$source_url" -o "$source_archive"
  tar -xzf "$source_archive" -C "$TMP_DIR"

  local source_dir
  source_dir="$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  if [[ -z "$source_dir" ]]; then
    echo "failed to unpack source archive" >&2
    exit 1
  fi

  ensure_sdk_for_source_build
  (
    cd "$source_dir"
    cargo build --release --locked --bin ida-cli
  )

  cp "$source_dir/target/release/ida-cli" "$REAL_BIN"
  chmod +x "$REAL_BIN"
}

normalize_idadir() {
  local path="${1:-}"
  if [[ -z "$path" ]]; then
    return 1
  fi

  case "$OS" in
    Darwin)
      case "$path" in
        *.app)
          printf '%s\n' "$path/Contents/MacOS"
          ;;
        */Contents)
          printf '%s\n' "$path/MacOS"
          ;;
        *)
          printf '%s\n' "$path"
          ;;
      esac
      ;;
    *)
      printf '%s\n' "$path"
      ;;
  esac
}

write_launcher() {
  cat >"$LAUNCHER" <<EOF
#!/usr/bin/env bash
set -euo pipefail

REAL_BIN="${REAL_BIN}"
IDA_ENV_NAME="${LIB_ENV}"
OS_NAME="\$(uname -s)"

normalize_idadir() {
  local path="\${1:-}"
  if [[ -z "\$path" ]]; then
    return 1
  fi

  case "\$OS_NAME" in
    Darwin)
      case "\$path" in
        *.app) printf '%s\n' "\$path/Contents/MacOS" ;;
        */Contents) printf '%s\n' "\$path/MacOS" ;;
        *) printf '%s\n' "\$path" ;;
      esac
      ;;
    *)
      printf '%s\n' "\$path"
      ;;
  esac
}

detect_idadir() {
  if [[ -n "\${IDADIR:-}" ]]; then
    normalize_idadir "\$IDADIR"
    return 0
  fi

  case "\$OS_NAME" in
    Darwin)
      local app candidate=""
      for app in /Applications/IDA\\ Professional*.app "\$HOME"/Applications/IDA\\ Professional*.app; do
        if [[ -d "\$app/Contents/MacOS" ]]; then
          candidate="\$app/Contents/MacOS"
        fi
      done
      if [[ -n "\$candidate" ]]; then
        printf '%s\n' "\$candidate"
        return 0
      fi
      ;;
    Linux)
      local dir candidate=""
      for dir in "\$HOME"/ida-pro /opt/ida* /opt/ida-pro* /usr/local/ida*; do
        if [[ -d "\$dir" ]]; then
          candidate="\$dir"
        fi
      done
      if [[ -n "\$candidate" ]]; then
        printf '%s\n' "\$candidate"
        return 0
      fi
      ;;
  esac

  return 1
}

IDA_RUNTIME_DIR="\$(detect_idadir || true)"
if [[ -n "\$IDA_RUNTIME_DIR" ]]; then
  export IDADIR="\$IDA_RUNTIME_DIR"
  case "\$IDA_ENV_NAME" in
    DYLD_LIBRARY_PATH)
      export DYLD_LIBRARY_PATH="\$IDA_RUNTIME_DIR\${DYLD_LIBRARY_PATH:+:\$DYLD_LIBRARY_PATH}"
      ;;
    LD_LIBRARY_PATH)
      export LD_LIBRARY_PATH="\$IDA_RUNTIME_DIR\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
      ;;
    PATH)
      export PATH="\$IDA_RUNTIME_DIR\${PATH:+:\$PATH}"
      ;;
  esac
fi

exec -a ida-cli "\$REAL_BIN" "\$@"
EOF
  chmod +x "$LAUNCHER"
}

add_path_entry() {
  if [[ ":$PATH:" == *":$BIN_DIR:"* ]]; then
    return 0
  fi

  local shell_name rc_file line
  shell_name="$(basename "${SHELL:-}")"
  case "$shell_name" in
    zsh)
      rc_file="$HOME/.zshrc"
      line="export PATH=\"$BIN_DIR:\$PATH\""
      ;;
    bash)
      rc_file="$HOME/.bashrc"
      line="export PATH=\"$BIN_DIR:\$PATH\""
      ;;
    fish)
      rc_file="$HOME/.config/fish/config.fish"
      line="fish_add_path \"$BIN_DIR\""
      ;;
    *)
      echo "installed to ${BIN_DIR}; add it to PATH manually" >&2
      return 0
      ;;
  esac

  mkdir -p "$(dirname "$rc_file")"
  touch "$rc_file"
  if ! grep -Fq "$line" "$rc_file"; then
    printf '\n%s\n' "$line" >>"$rc_file"
  fi
}

if [[ "$BUILD_FROM_SOURCE" -eq 1 || -n "$REF" ]]; then
  build_from_source
else
  if ! download_release_asset; then
    echo "release asset unavailable, falling back to a local source build"
    build_from_source
  fi
fi

write_launcher

if [[ "$ADD_PATH" -eq 1 ]]; then
  add_path_entry
fi

echo "installed:"
echo "  launcher: $LAUNCHER"
echo "  binary:   $REAL_BIN"
if [[ "$ADD_PATH" -eq 0 && ":$PATH:" != *":$BIN_DIR:"* ]]; then
  echo "add this to PATH:"
  echo "  export PATH=\"$BIN_DIR:\$PATH\""
fi
echo "skill install:"
echo "  npx -y skills add https://github.com/${REPO} --skill ida --agent codex --yes --global"
