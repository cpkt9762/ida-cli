#!/usr/bin/env bash
# Install a Nexus-only bundle and a dedicated, hash-checked Python environment.
set -euo pipefail
REPO="${IDA_CLI_REPO:-cpkt9762/ida-cli}"
BIN_DIR="${IDA_CLI_BIN_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}"
INSTALL_ROOT="${IDA_CLI_INSTALL_ROOT:-${XDG_DATA_HOME:-$HOME/.local/share}/ida-cli}"
TAG="" REF="" BUNDLE="" SOURCE="" WHEELS="" BUILD=0 KEEP=0 ADD_PATH=0
usage() {
  cat <<'EOF'
Install the Nexus-only ida-cli release (IDA >=9.4, Python >=3.11).
  --tag TAG | --ref REF | --build-from-source
  --bin-dir DIR --install-root DIR --add-path --keep-temp
  --bundle DIR          Install an already extracted release bundle
  --nexus-source DIR    Read-only pinned Nexus clone for offline preparation
  --wheels DIR          Read-only hashed wheel directory
IDADIR overrides automatic discovery. A unique macOS IDA installation is selected;
multiple or missing installations require an explicit IDADIR. Rust needs no SDK.
EOF
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="${2:?}"; shift 2 ;;
    --ref) REF="${2:?}"; BUILD=1; shift 2 ;;
    --bin-dir) BIN_DIR="${2:?}"; shift 2 ;;
    --install-root) INSTALL_ROOT="${2:?}"; shift 2 ;;
    --bundle) BUNDLE="${2:?}"; shift 2 ;;
    --nexus-source) SOURCE="${2:?}"; shift 2 ;;
    --wheels) WHEELS="${2:?}"; shift 2 ;;
    --build-from-source) BUILD=1; shift ;;
    --keep-temp) KEEP=1; shift ;;
    --add-path) ADD_PATH=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done
for tool in python3 tar mktemp; do command -v "$tool" >/dev/null || { echo "missing command: $tool" >&2; exit 1; }; done
TMP_DIR="$(mktemp -d)"
cleanup() { if [[ "$KEEP" == 0 ]]; then rm -rf "$TMP_DIR"; else echo "kept: $TMP_DIR"; fi; }
trap cleanup EXIT
if [[ -z "$BUNDLE" ]]; then
  command -v curl >/dev/null
  if [[ "$BUILD" == 1 ]]; then
    command -v cargo >/dev/null
    source_url="https://github.com/${REPO}/archive/refs/heads/${REF:-master}.tar.gz"
    [[ -z "$TAG" ]] || source_url="https://github.com/${REPO}/archive/refs/tags/${TAG}.tar.gz"
    curl -fsSL "$source_url" -o "$TMP_DIR/source.tar.gz"
    mkdir "$TMP_DIR/source"
    tar -xzf "$TMP_DIR/source.tar.gz" --strip-components=1 -C "$TMP_DIR/source"
    # Python owns the build timeout; no dependency on GNU coreutils on macOS.
    python3 - "$TMP_DIR/source" "$TMP_DIR/target" <<'PY'
import os, signal, subprocess, sys
with subprocess.Popen(['cargo', 'build', '--release', '--locked', '--bin', 'ida-cli'],
        cwd=sys.argv[1], env=os.environ | {'CARGO_TARGET_DIR': sys.argv[2]}, start_new_session=True) as child:
    try:
        code = child.wait(timeout=180)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
        raise SystemExit('source build exceeded 180s')
    if code:
        raise SystemExit(code)
PY
    BUNDLE="$TMP_DIR/source"
    cp "$TMP_DIR/target/release/ida-cli" "$BUNDLE/ida-cli"
  else
    platform="$(uname -s)"; arch="$(uname -m)"
    case "$platform/$arch" in Darwin/arm64|Linux/x86_64) ;; *) echo 'unsupported release platform' >&2; exit 1 ;; esac
    asset="ida-cli-${platform}_${arch}.tar.gz"
    base="https://github.com/${REPO}/releases/latest/download"
    [[ -z "$TAG" ]] || base="https://github.com/${REPO}/releases/download/${TAG}"
    curl -fsSL "$base/$asset" -o "$TMP_DIR/$asset"
    curl -fsSL "$base/sha256sums.txt" -o "$TMP_DIR/sha256sums.txt"
    python3 - "$TMP_DIR" "$asset" <<'PY'
import hashlib, pathlib, sys
root, name = pathlib.Path(sys.argv[1]), sys.argv[2]
expected = [line.split()[0] for line in (root/'sha256sums.txt').read_text().splitlines()
            if pathlib.PurePosixPath(line.split()[-1]).name == name]
if expected != [hashlib.sha256((root/name).read_bytes()).hexdigest()]:
    raise SystemExit('release archive hash mismatch')
PY
    mkdir "$TMP_DIR/bundle"
    tar -xzf "$TMP_DIR/$asset" -C "$TMP_DIR/bundle"
    BUNDLE="$TMP_DIR/bundle"
  fi
fi
# Refuse incomplete/old releases before changing the installation prefix.
[[ -f "$BUNDLE/ida-cli" && -f "$BUNDLE/scripts/nexus/runtime-lock.json" ]] || { echo 'Nexus bundle is incomplete' >&2; exit 1; }
python3 - "$BUNDLE" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])/'scripts/nexus'
lock = json.loads((root/'runtime-lock.json').read_text())
for name, expected in lock['assets'].items():
    if pathlib.PurePath(name).name != name or hashlib.sha256((root/name).read_bytes()).hexdigest() != expected:
        raise SystemExit('runtime asset hash mismatch: '+name)
PY
IDADIR="$(python3 -I -B "$BUNDLE/scripts/prepare_nexus_env.py" --detect-ida)"
export IDADIR
mkdir -p "$INSTALL_ROOT" "$BIN_DIR"
INSTALL_ROOT="$(cd "$INSTALL_ROOT" && pwd -P)"
BIN_DIR="$(cd "$BIN_DIR" && pwd -P)"
# Stage a complete version first; a failed preparation leaves the active launcher intact.
VERSION_ROOT="$(mktemp -d "$INSTALL_ROOT/version.XXXXXX")"
mkdir -p "$VERSION_ROOT/scripts/nexus"
cp "$BUNDLE/ida-cli" "$VERSION_ROOT/ida-cli.real"
cp "$BUNDLE/scripts/prepare_nexus_env.py" "$VERSION_ROOT/scripts/"
cp "$BUNDLE/scripts/nexus/"*.patch "$BUNDLE/scripts/nexus/"*.json "$BUNDLE/scripts/nexus/requirements.lock" "$VERSION_ROOT/scripts/nexus/"
chmod 700 "$VERSION_ROOT/ida-cli.real"
args=(--runtime-only --root "$VERSION_ROOT/nexus" --ida-dir "$IDADIR")
[[ -z "$SOURCE" ]] || args+=(--source "$SOURCE")
[[ -z "$WHEELS" ]] || args+=(--wheels "$WHEELS")
python3 "$VERSION_ROOT/scripts/prepare_nexus_env.py" "${args[@]}"
# Generate quoted shell assignments without interpolating paths as shell code.
python3 - "$VERSION_ROOT" "$BIN_DIR/ida-cli" <<'PY'
import pathlib, shlex, sys
root, launcher = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
quote = shlex.quote
text = ('#!/usr/bin/env bash\nset -euo pipefail\n'
        'export IDA_NEXUS_PYTHON='+quote(str(root/'nexus/venv/bin/python'))+'\n'
        'IDADIR="$("$IDA_NEXUS_PYTHON" -I -B '+quote(str(root/'scripts/prepare_nexus_env.py'))+' --detect-ida)"\n'
        'export IDADIR\n'
        'exec -a ida-cli '+quote(str(root/'ida-cli.real'))+' "$@"\n')
staged = launcher.with_name('.ida-cli.new')
with staged.open('x') as stream:
    stream.write(text)
staged.chmod(0o700)
staged.replace(launcher)
PY
if [[ "$ADD_PATH" == 1 ]]; then
  python3 - "$BIN_DIR" <<'PYTHON'
import os, pathlib, shlex, sys
rc = pathlib.Path.home()/('.zshrc' if pathlib.Path(os.environ.get('SHELL', '')).name == 'zsh' else '.bashrc')
line = 'export PATH='+shlex.quote(sys.argv[1])+':"$PATH"'
existing = rc.read_text() if rc.exists() else ''
if line not in existing.splitlines():
    with rc.open('a') as stream:
        stream.write('\n'+line+'\n')
PYTHON
fi
echo "Installed Nexus-only ida-cli: $BIN_DIR/ida-cli"
