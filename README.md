# ida-cli

Headless IDA CLI and skill-first toolkit for binary analysis on macOS and
Linux. `ida-cli` auto-selects a runtime backend, auto-starts a local server
when needed, and exposes the same surface as a flat CLI, a stdio MCP
transport, and a Streamable HTTP MCP transport.

[中文说明](README.zh-CN.md)

## Two User-Facing Entrypoints

- the local `ida-cli` binary (client + service in one executable)
- the installable `ida-cli` skill (`skill/SKILL.md`) for agent environments

The underlying worker / router service layer is started and shut down by the
CLI automatically. You only need to run `serve` / `serve-http` explicitly
when you actually want a long-lived, externally addressable service.

## Support Matrix

### Host Platforms

- Supported: macOS, Linux
- Not supported: Windows

### IDA Runtime Policy

Runtime requirements: IDA 9.4/9.5 and Python >=3.11. All database operations use the dedicated pinned Nexus 0.13.4 / Domain 0.5.1 environment. Missing dependencies or mismatched patches fail explicitly. Rust builds need no IDA SDK.

## Current Capabilities

On supported IDA 9.x runtimes, `ida-cli` can:

- open raw PE / ELF / Mach-O binaries and reuse cached `.i64` databases
- list and resolve functions, disassemble by address or name, decompile via
  Hex-Rays
- query segments, strings, imports, exports, entry points, global symbols
- resolve address ↔ segment / function / symbol context
- read bytes / strings / integers, apply `read_*` and `convert_number` helpers
- query xrefs to / from an address (including xrefs to strings and struct
  fields)
- build callgraphs, basic blocks, and control-flow paths
- search text, immediates, bytes, instructions, operands, pseudocode
- declare / apply types, rename symbols and locals, set comments
- run IDAPython snippets via `run_script`

All tools use Nexus with explicit capability errors. See [docs/TOOLS.md](docs/TOOLS.md) for the
generated tool list.

## Quick Start

### Recommended: Install the Skill

The default entrypoint is the `ida-cli` skill, not a manual CLI install.

```bash
# list the skill exposed by this repository
npx -y skills add https://github.com/cpkt9762/ida-cli --list

# install the ida-cli skill for Codex
npx -y skills add https://github.com/cpkt9762/ida-cli --skill ida-cli --agent codex --yes --global
```

After install, the skill ships its own bootstrap wrapper:

```bash
~/.agents/skills/ida-cli/scripts/ida-cli.sh --help
~/.agents/skills/ida-cli/scripts/ida-cli.sh probe-runtime
~/.agents/skills/ida-cli/scripts/ida-cli.sh --path /path/to/binary list-functions --limit 20
```

If `ida-cli` is missing, the wrapper installs it through the repository
installer before forwarding the command.

### Direct CLI Install (Optional)

Use this only if you want the standalone CLI without going through the
skill.

```bash
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --add-path
```

Useful variants:

```bash
# install a specific release
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --tag v0.9.3 --add-path

# build directly from a branch or ref
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --ref master --build-from-source --add-path
```

Notes:

- The installer places the launcher in `~/.local/bin/ida-cli` by default.
- `--add-path` appends that bin directory to your shell rc file.
- The installer creates a dedicated Python environment and verifies all four patches, dependency hashes and installed module hashes.
- On macOS, installation selects the newest numeric `.app` version under `/Applications` or `~/Applications` and prints the selected and other candidates. `9.10` is newer than `9.9`; trailing zero components are equal, with canonical path order breaking ties. Explicit `IDADIR` takes priority. An incompatible selected wheel/runtime fails explicitly. If no candidate is found, installation fails with instructions to set `IDADIR`.
- The launcher stores the runtime selected at installation and uses it without rediscovery. Explicit `IDADIR` overrides it; `.app`, `Contents` and runtime paths are accepted. See [version comparison and runtime checks](docs/BUILDING.md).

### Build from Source

```bash
git clone https://github.com/cpkt9762/ida-cli.git
cd ida-cli

export IDADIR="/Applications/IDA Professional 9.5.app/Contents/MacOS"   # or a Linux install

cargo build --bin ida-cli
./target/debug/ida-cli --help
```

### Use the CLI

`ida-cli` is client-first. Any client subcommand auto-starts a local
Streamable-HTTP server bound to a random port and writes
`/tmp/ida-cli.socket` for discovery:

```bash
./target/debug/ida-cli --path /path/to/sample.bin list-functions --limit 20
./target/debug/ida-cli --path /path/to/sample.bin decompile --addr 0x140001000
./target/debug/ida-cli --path /path/to/sample.bin raw '{"method":"get_xrefs_to","params":{"address":"0x140001000"}}'
```

To see which databases the daemon currently holds open, and which clients
hold them, run `list-idbs` (MCP tool: `list_idbs`). Run it before rebuilding
or replacing an `.i64`, for example with `idat`: a database that is still
listed is held open by the daemon, and `idat` fails on a database that is
open elsewhere. The answer is `{"count": N, "idbs": [...]}`; each entry has
the `db_handle`, the input path and the `.i64` path, an opaque id of the
client that opened it, when it was opened, the worker process, whether it is
the active database, and the clients that still hold references. Close
tokens are never returned.

```bash
./target/debug/ida-cli list-idbs --json
```

To get the address behind each line of pseudocode, add `--line-addresses` to
`decompile` (MCP and RPC: `line_addresses: true` on `decompile_function`). The
answer becomes `{"code": ..., "lines": [...]}`: `code` is the usual text and
each `lines` entry is `{"line", "text", "addresses"}`. `line` counts from 1,
`text` is that line of `code`, and `addresses` are the IDA addresses (hex
strings, ascending, no duplicates) of the ctree items Hex-Rays anchored on the
line. A line can map to several non-contiguous addresses, and the list is not
every instruction of the statement. The signature and local declarations have
none; `{`, `}`, `else` and blank lines can carry the address of the block or
`if` that owns them (the function entry for the outermost braces). The `sub_`
rename hint is not added in this mode. Hex-Rays can print a very large function
differently from one call to the next, so use `code` and `lines` from the same
answer only. Nexus supports this mode. Over the CLI socket a large
answer is stored in the response cache like any other (`IDA_MCP_MAX_INLINE_BYTES`).

```json
{"line": 6, "text": "  while ( a1 != 1 )", "addresses": ["0x10000033c", "0x100000340"]}
```

Commands whose first argument is a service subcommand (`serve`,
`serve-http`, `serve-worker`, `probe-runtime`) enter service mode instead:

```bash
./target/debug/ida-cli serve                          # stdio MCP transport
./target/debug/ida-cli serve-http --bind 127.0.0.1:8765
./target/debug/ida-cli probe-runtime
```

`probe-runtime` checks Nexus dependencies, patches and protocol readiness; mismatches exit nonzero.

For the complete CLI surface see
[skill/references/cli-tool-reference.md](skill/references/cli-tool-reference.md).

## Build Requirements

- Rust 1.87+
- macOS or Linux host
- An IDA installation via `IDADIR` (runtime support starts at IDA 9.4)

## Runtime Notes

### Nexus

The launcher locates its dedicated Python environment; source builds can set `IDA_NEXUS_PYTHON`. Offline sBPF/DSC preparation still uses sbx/idat; ordinary queries, edits and database sessions use Nexus. Rollback uses the fixed N0 executable and a closed pre-migration backup in a separate recovery directory. Installing or switching a real environment requires explicit authorization.

### Cache and Local Runtime Paths

- Database cache: `~/.ida/idb/`
- Logs: `~/.ida/logs/server.log`
- Server Unix socket: `~/.ida/server.sock`
- Server PID file: `~/.ida/server.pid`
- CLI discovery file (maps the flat CLI to the live socket): `/tmp/ida-cli.socket`
- Large JSON response cache: `/tmp/ida-cli-out/`

## CI and Releases

GitHub Actions compiles and tests the tree on hosted runners against the
open-source `HexRaysSA/ida-sdk`, so CI does not depend on any private
machine layout.

Current workflow behavior:

- pushes and pull requests against `master` run validation
- tagged pushes like `v0.9.3` build release archives for Linux and macOS
- releases attach `install.sh` plus platform archives

Release binaries have no IDA linkage. The installer creates and directly locates the pinned, four-patch Nexus Python environment.

## Documentation

- [docs/BUILDING.md](docs/BUILDING.md) — build from source
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — router, backends, federation
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md) — stdio, streamable HTTP, multi-IDB
- [docs/TOOLS.md](docs/TOOLS.md) — generated tool catalog
- [docs/TESTING.md](docs/TESTING.md) — integration and unit tests
- [skill/SKILL.md](skill/SKILL.md) — skill bootstrap and usage policy
- [skill/references/cli-tool-reference.md](skill/references/cli-tool-reference.md) — complete CLI surface

## License

MIT

Removed configuration is an error (even an empty value), before CLI daemon discovery or server startup: `IDA_CLI_NEXUS_DEV`, `IDA_CLI_WORKER_BACKEND`, `IDA_CLI_SDK_VERSION`, `IDA_CLI_MAX_WORKERS`, `IDA_CLI_MAX_WORKERS_PER_TENANT`, `IDA_CLI_MAX_PENDING_PER_WORKER`, `IDA_CLI_MAX_CONCURRENT_SPAWNS`. Remove these variables. For Nexus limits use the applicable `IDA_CLI_MAX_PENDING_PER_TENANT`, `IDA_CLI_NEXUS_RETENTION_CAPACITY`, or `IDA_CLI_HELPER_CAPACITY`; these are independent limits, not direct replacements for worker counts.

The runtime lock has a separate wheel name and SHA256 for each supported IDA version: 9.4 uses idapro 0.0.9, 9.5 uses 0.0.10. Domain 0.5.1 declares idapro>=0.0.10; the 9.4 entry accepts only that exact metadata conflict after the installed `__init__.py` and `config.py` match the registered hashes (both are byte-identical to 0.0.10). Domain supports IDA >=9.1 and gates newer APIs. The entire hashed closure installs with `--no-deps`; every other pip check conflict fails.

The installer compares numeric dotted app-name versions component by component, ignores trailing zero components and breaks equal-version ties by canonical path. It prints the other candidates. An incompatible newest candidate fails with explicit IDADIR guidance; it never selects an older candidate automatically. The launcher freezes the selected path. A bounded database-free kernel probe and subsequent owner checks verify the actual runtime.

N0 comparisons are valid only with IDA 9.5. At 9.4 the verifier reports BLOCKED for suites requiring N0. Contract `--case E16`, `E17` and `E22` can run independently; E22 generates an annotated 9.4 database in the historical flat-cache layout and checks reuse/prewarm, without claiming an N0 comparison.

Supported IDA runtimes: **9.4 and 9.5** only. Each uses its own locked wheel. For 9.4 only, the Domain metadata exception is conditional on exact installed runtime code hashes; every other dependency conflict fails. An explicit IDADIR override may switch between supported versions; reinstall for the target version is recommended. probe-runtime/status distinguish actual and installation versions. N0 comparisons require 9.5.

Sequential CLI path queries reuse one daemon-owned warm lease instead of
reopening IDA for each socket connection. `IDA_CLI_MAX_WARM_WORKERS` bounds
this pool (default 16); least recently used entries are released when full.
Use `ida-cli --path <file> close` or `shutdown` to release it. MCP openers keep
independent leases and close tokens. Closed observation details retain at most
128 settled records; active/unknown obligations are never evicted. Older proof
files remain in custody journals, while request/operation identity tombstones
keep the existing `IDA_CLI_NEXUS_RETENTION_CAPACITY` limit and no-replay rules.
