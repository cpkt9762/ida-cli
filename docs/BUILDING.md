# Building from Source

Rust builds need a host Rust toolchain; no IDA SDK, native IDA libraries or LLVM headers are linked. Database execution uses only Nexus. IDA >=9.4, Python >=3.11 and a legally prepared IDA runtime are required for analysis. Missing dependencies and patch mismatches fail explicitly at startup.

```bash
timeout 180s cargo build --locked --release --bin ida-cli
```

Release archives contain the binary, installer, environment preparer, dependency lock, SDK contract and all four patches: loopback-bind, client-cancel-unknown, client-close-proof and client-acquisition. `scripts/nexus/runtime-lock.json` fixes their hashes, Nexus commit, dependency versions and installed module hashes. `scripts/package_release.py` refuses mismatched assets. No IDA proprietary files are distributed.

```bash
python3 scripts/package_release.py --binary target/release/ida-cli --output /tmp/ida-cli-bundle.tar.gz
```

The installer creates a dedicated Python environment under its version directory, installs hashed dependencies, validates the selected IDA-provided idapro wheel, applies the fixed patch chain, verifies the resulting source and actual installed modules, then atomically replaces the launcher. It does not read an IDA profile or accept terms. On macOS, installation discovers `/Applications/IDA Professional*.app` and `~/Applications/IDA Professional*.app`. Explicit `IDADIR` takes priority and accepts `.app`, `Contents` or runtime directories. Otherwise it chooses the newest version from the app name and prints the selected and other candidates. No candidate fails with the search paths and explicit `IDADIR` guidance. The launcher embeds the selected canonical runtime as its default; it does not rediscover installations at launch. Explicit `IDADIR` still overrides that default. Other platforms require explicit `IDADIR`. `IDA_CLI_IDA_SEARCH_ROOTS` can replace the search roots with a JSON array of absolute directories (used by private discovery tests). `--bin-dir` and `--install-root` support private installation rehearsals. `--bundle`, `--nexus-source` and `--wheels` accept local read-only inputs. Failed preparation retains the staged version and logs, leaving the previous launcher active.

For a source build, set `IDA_NEXUS_PYTHON` to a prepared environment's absolute `venv/bin/python`. The installed launcher sets this directly. `probe-runtime` performs the same verified Nexus handshake without opening a database; missing/old runtime or incompatible modules return an error. On successful completion it explicitly waits for its bridge and helper, then removes only recorded probe entries and sockets after checking their creation identities. Unknown/replaced entries are retained and reported; ordinary session evidence and abnormal orphan recovery are unchanged. There is no backend selector. Python/native maintenance budgets run in-process and do not require GNU coreutils.

`IDA_CLI_HOME` defaults to `~/.ida` for every frontend. `IDA_NEXUS_IPC_ROOT` optionally chooses a short private parent for bridge endpoints; otherwise the host temporary directory is used. Keep independent home/state/profile/input copies for tests. Offline sbx/idat preparation is retained for sBPF/DSC and never handles ordinary database requests.

Rollback is version-level: retain the fixed N0 executable, matching IDA runtime and closed pre-migration backup. Stop new requests, wait for completion or cancellation evidence, preserve the migrated database, release only owned leases and wait for owner exit before copying. Restore into a separate directory and invoke the old executable directly. Never open a new-runtime database with the old runtime or overwrite real data during rehearsal. Actual installation, daemon restart and rollback require explicit user authorization.

App versions are the ASCII dotted integer components immediately after `IDA Professional `; comparison is numeric from left to right, with missing trailing components treated as zero (`9.10 > 9.9`, `10.0 > 9.50`, `9.5 == 9.5.0`). Suffixes after that numeric prefix do not affect ordering. Names without a numeric version rank below numeric versions. Canonical aliases are deduplicated, retaining their highest named version; ties select the lexicographically smallest canonical runtime path.

Before creating a new installation prefix, the selected runtime must pass the existing Python >=3.11, IDA bundle version >=9.4 and exact IDA-provided idapro wheel version/SHA256 checks. Preparation then validates the pinned Nexus/Domain dependency environment and patched modules. A failed selected runtime stops installation; it never silently selects an older candidate. Failed preparation leaves the previous launcher active.

唯一 Nexus 后端在 CLI 发现 daemon 或服务启动前拒绝已删除配置（包括空值）：`IDA_CLI_NEXUS_DEV`、`IDA_CLI_WORKER_BACKEND`、`IDA_CLI_SDK_VERSION`、`IDA_CLI_MAX_WORKERS`、`IDA_CLI_MAX_WORKERS_PER_TENANT`、`IDA_CLI_MAX_PENDING_PER_WORKER`、`IDA_CLI_MAX_CONCURRENT_SPAWNS`。请删除这些变量；按实际需求配置 `IDA_CLI_MAX_PENDING_PER_TENANT`、`IDA_CLI_NEXUS_RETENTION_CAPACITY` 或 `IDA_CLI_HELPER_CAPACITY`。它们是独立限制，不与旧 worker 数量一一对应。
