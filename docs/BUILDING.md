# Building from Source

## Requirements

- Rust 1.77+
- LLVM/Clang
- An IDA installation, provided via `IDADIR` or discoverable from common paths
- An IDA SDK, provided via `IDASDKDIR` or `IDALIB_SDK`

`ida-cli` uses two runtime strategies:

- `native-linked`
  Uses the vendored `idalib` backend for newer compatible runtimes.
- `idat-compat`
  Uses `idat` + IDAPython for older runtimes where in-process database opening is unsafe.

That means the build is not restricted to one exact installed IDA runtime, but the SDK must still be present for compiling the vendored `idalib` layer.

## Clone and Build

```bash
git clone https://github.com/gmh5225/ida-cli.git
cd ida-cli

export IDADIR="/Applications/IDA Professional 9.1.app/Contents/MacOS"
export IDASDKDIR="/path/to/ida-sdk"

cargo build --bin ida-cli
```

Release build:

```bash
cargo build --release --bin ida-cli
```

## SDK Path Rules

The SDK path may point to either:

- the SDK root, for example `/path/to/ida-sdk`
- the nested `src` directory, for example `/path/to/ida-sdk/src`

The build logic accepts both layouts as long as it can find:

- `include/pro.h`
- platform libraries under `lib/...`

## Runtime Selection

At runtime, `ida-cli` probes the active IDA installation and selects a worker backend automatically.

Example:

```bash
./target/debug/ida-cli probe-runtime
```

Typical outputs:

```json
{"runtime":{"major":9,"minor":0,"build":250226},"backend":"idat-compat","supported":true,"reason":null}
```

```json
{"runtime":{"major":9,"minor":3,"build":260213},"backend":"native-linked","supported":true,"reason":null}
```

## Binary Names

The primary executable is:

- macOS/Linux: `target/debug/ida-cli` or `target/release/ida-cli`
- Windows: `target/debug/ida-cli.exe` or `target/release/ida-cli.exe`

## Common Commands

Start the local server:

```bash
./target/debug/ida-cli serve
```

Use the flat CLI:

```bash
./target/debug/ida-cli --path /path/to/binary list-functions --limit 20
./target/debug/ida-cli --path /path/to/binary decompile --addr 0x140001000
```

Run over HTTP:

```bash
./target/debug/ida-cli serve-http --bind 127.0.0.1:8765
```

## Output Paths

- Server log: `~/.ida/logs/server.log`
- Cached databases: `~/.ida/idb/`
- CLI discovery socket: `/tmp/ida-cli.socket`
- Large response cache: `/tmp/ida-cli-out/`

## Notes

- Building is native-only. Cross-compilation is not supported.
- If you are using an older runtime such as the tested local 9.1 installation, the CLI can still work through `idat-compat`, but compile-time SDK requirements remain.
