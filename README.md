# ida-cli

Headless IDA CLI and skill-first toolkit for binary analysis on macOS and Linux, with automatic runtime backend selection.

[中文说明](README.zh-CN.md)

## Overview

`ida-cli` is centered on two user-facing entrypoints:

- the local `ida-cli` command-line interface
- the installable `ida-cli` skill for agent environments

The underlying service layer is started and managed automatically by the CLI when needed.

## Support Matrix

### Host platforms

- Supported: macOS, Linux
- Not supported: Windows

### IDA runtime policy

- `IDA < 9.0`: unsupported
- `IDA 9.0 – 9.2`: `idat-compat`
  Uses `idat` + IDAPython as the compatibility path.
- `IDA 9.3+`: `native-linked`
  Uses the vendored `idalib` path when the runtime is safe to open in-process.

This backend choice is made at runtime by `probe-runtime`. Build-time SDK requirements are separate: the vendored native layer still needs an IDA SDK present during compilation.

It uses two runtime modes:

- `idat-compat`
  For IDA 9.0-9.2. This path shells out through `idat` and IDAPython.
- `native-linked`
  For IDA 9.3+ runtimes that can safely open databases in-process.

## What Works Today

On supported IDA 9.x runtimes, `ida-cli` can already:

- Open raw binaries and reuse cached databases
- List and resolve functions
- Disassemble by address or function
- Decompile functions
- Show address info, segments, strings, imports, exports, entry points, globals
- Read bytes, strings, and integers
- Query xrefs to/from an address
- Search text and byte patterns
- Run IDAPython snippets

The sample `example2-devirt.bin` was verified end-to-end:

- `list-functions` found `main` at `0x140001000`
- `decompile --addr 0x140001000` succeeded

Some write-heavy and advanced type-editing operations still require further parity work in `idat-compat`.

## Quick Start

### Recommended Path: Install the Skill

The default entrypoint is the `ida-cli` skill, not a manual CLI install.

```bash
# List the skill exposed by this repository
npx -y skills add https://github.com/cpkt9762/ida-cli --list

# Install the ida-cli skill for Codex
npx -y skills add https://github.com/cpkt9762/ida-cli --skill ida-cli --agent codex --yes --global
```

This was verified locally: the CLI detected the `ida-cli` skill from `skill/SKILL.md` and installed it to `~/.agents/skills/ida-cli`.

After installation, the skill ships its own bootstrap wrapper:

```bash
~/.agents/skills/ida-cli/scripts/ida-cli.sh --help
~/.agents/skills/ida-cli/scripts/ida-cli.sh probe-runtime
~/.agents/skills/ida-cli/scripts/ida-cli.sh --path /path/to/binary list-functions --limit 20
```

That wrapper installs `ida-cli` automatically if it is missing, then runs the requested command.

### Direct CLI Install (Optional)

Use this only if you want the standalone CLI without going through the skill.

```bash
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --add-path
```

Useful variants:

```bash
# Install a specific release
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --tag v0.9.3 --add-path

# Build directly from a branch or ref
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --ref master --build-from-source --add-path
```

Notes:

- The installer places the launcher in `~/.local/bin/ida-cli` by default.
- `--add-path` appends that bin directory to your shell rc file.
- If `IDASDKDIR` / `IDALIB_SDK` is not already set and the script needs a local build, it will clone the open-source `HexRaysSA/ida-sdk` automatically.
- If you keep multiple IDA installations side by side, export `IDADIR` explicitly before installing or running `ida-cli`.

### Build from source

```bash
git clone https://github.com/cpkt9762/ida-cli.git
cd ida-cli

export IDADIR="/path/to/ida"
export IDASDKDIR="/path/to/ida-sdk"

cargo build --bin ida-cli
./target/debug/ida-cli --help
```

### Use the CLI

```bash
./target/debug/ida-cli --path /path/to/example2-devirt.bin list-functions --limit 20
./target/debug/ida-cli --path /path/to/example2-devirt.bin decompile --addr 0x140001000
./target/debug/ida-cli --path /path/to/example2-devirt.bin raw '{"method":"get_xrefs_to","params":{"path":"/path/to/example2-devirt.bin","address":"0x140001000"}}'
```

### Probe the selected runtime backend

```bash
./target/debug/ida-cli probe-runtime
```

Example backend selections:

```json
{"runtime":{"major":9,"minor":1,"build":250226},"backend":"idat-compat","supported":true,"reason":null}
```

```json
{"runtime":{"major":9,"minor":3,"build":260213},"backend":"native-linked","supported":true,"reason":null}
```

## Build Requirements

- Rust 1.77+
- LLVM/Clang
- macOS or Linux host
- IDA installation via `IDADIR` (runtime support starts at IDA 9.0)
- IDA SDK via `IDASDKDIR` or `IDALIB_SDK`

The SDK lookup accepts both layouts:

- `/path/to/ida-sdk`
- `/path/to/ida-sdk/src`

## Runtime Notes

### `idat-compat`

This backend shells out to `idat`, runs short IDAPython scripts, and returns structured results back to the CLI runtime. It is the compatibility path for IDA 9.0-9.2 and the fallback for runtimes that should not open databases in-process.

### `native-linked`

This backend links against the vendored `idalib` line and is intended for IDA 9.3+ runtimes.

### Cache and local runtime paths

- Database cache: `~/.ida/idb/`
- Logs: `~/.ida/logs/server.log`
- CLI discovery socket: `/tmp/ida-cli.socket`
- Large JSON response cache: `/tmp/ida-cli-out/`

## CI and Releases

GitHub Actions now uses the open-source `HexRaysSA/ida-sdk` on hosted runners so it can compile and test the current tree without relying on a private machine layout.

Current workflow behavior:

- Pushes and pull requests against `master` run validation
- Tagged pushes like `v0.9.3` build release archives for Linux and macOS
- Releases attach `install.sh` plus platform archives

The release archives are built against SDK stubs, while the installed launcher resolves your local IDA runtime through `IDADIR` or common install paths before starting `ida-cli`.

## Documentation

- [docs/BUILDING.md](docs/BUILDING.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md)
- [docs/TOOLS.md](docs/TOOLS.md)

## License

MIT
