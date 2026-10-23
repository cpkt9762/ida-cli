# Building from Source

Rust builds need a host Rust toolchain; no IDA SDK, native IDA libraries or LLVM headers are linked. Database execution uses only Nexus. IDA 9.4/9.5, Python >=3.11 and a legally prepared IDA runtime are required for analysis. Missing dependencies and patch mismatches fail explicitly at startup.

```bash
timeout 180s cargo build --locked --release --bin ida-cli
```

Release archives contain the binary, installer, environment preparer, dependency lock, SDK contract and all five patches: loopback-bind, client-cancel-unknown, client-close-proof, client-acquisition and launch-authorization. `scripts/nexus/runtime-lock.json` fixes their hashes, Nexus commit, dependency versions and installed module hashes. `scripts/package_release.py` refuses mismatched assets. No IDA proprietary files are distributed.

```bash
python3 scripts/package_release.py --binary target/release/ida-cli --output /tmp/ida-cli-bundle.tar.gz
```

The installer creates a dedicated Python environment under its version directory, installs hashed dependencies, validates the selected IDA-provided idapro wheel, applies the fixed patch chain, verifies the resulting source and actual installed modules, then atomically replaces the launcher. It does not read an IDA profile or accept terms. On macOS, installation discovers `/Applications/IDA Professional*.app` and `~/Applications/IDA Professional*.app`. Explicit `IDADIR` takes priority and accepts `.app`, `Contents` or runtime directories. Otherwise it chooses the newest version from the app name and prints the selected and other candidates. No candidate fails with the search paths and explicit `IDADIR` guidance. The launcher embeds the selected canonical runtime as its default; it does not rediscover installations at launch. Explicit `IDADIR` still overrides that default. Other platforms require explicit `IDADIR`. `IDA_CLI_IDA_SEARCH_ROOTS` can replace the search roots with a JSON array of absolute directories (used by private discovery tests). `--bin-dir` and `--install-root` support private installation rehearsals. `--bundle`, `--nexus-source` and `--wheels` accept local read-only inputs. Failed preparation retains the staged version and logs, leaving the previous launcher active.

For a source build, set `IDA_NEXUS_PYTHON` to a prepared environment's absolute `venv/bin/python`. The installed launcher sets this directly. `probe-runtime` performs the same verified Nexus handshake without opening a database; missing/old runtime or incompatible modules return an error. On successful completion it explicitly waits for its bridge and helper, then removes only recorded probe entries and sockets after checking their creation identities. Unknown/replaced entries are retained and reported; ordinary session evidence and abnormal orphan recovery are unchanged. There is no backend selector. Python/native maintenance budgets run in-process and do not require GNU coreutils.

`IDA_CLI_HOME` defaults to `~/.ida` for every frontend. `IDA_NEXUS_IPC_ROOT` optionally chooses a short private parent for bridge endpoints; otherwise the host temporary directory is used. Each daemon atomically creates a fresh `n4-<pid>-<n>` directory under it. Allocation skips existing names (including symlinks) without reading or modifying them, trying up to 1024 successive sequence numbers. This handles PID reuse while preserving old session evidence. Exhaustion reports the last path and attempt count; other creation errors immediately report the full path. Only a newly created directory is owned and initialized. Sockets are removed on shutdown, but the directory is deliberately kept: `stderr.log`, `helper.log`, `helper-state.json` and `installation/` (about 800KB) are the durable session evidence, and `helper-state.json` is the helper's durable obligation registry (`finishing`, obligations) that shutdown and orphan recovery rely on. Only `probe-runtime` (no acquisition history) deletes its own entries. A directory containing `launch-authorizations/` must be retained even after confirmed shutdown: grant/decision files permanently fence children delayed before claim. Do not remove or recreate those files or their directory. For a directory without launch authorizations, deletion by hand requires its `<pid>` to be no longer a running `ida-cli` and the last stop to have been a confirmed `ida-cli shutdown`; after a crash or kill retain it until you have inspected `helper-state.json`. Keep independent home/state/profile/input copies for tests. Offline sbx/idat preparation is retained for sBPF/DSC and never handles ordinary database requests.

Rollback is version-level: retain the fixed N0 executable, matching IDA runtime and closed pre-migration backup. Stop new requests, wait for completion or cancellation evidence, preserve the migrated database, release only owned leases and wait for owner exit before copying. Restore into a separate directory and invoke the old executable directly. Never open a new-runtime database with the old runtime or overwrite real data during rehearsal. Actual installation, daemon restart and rollback require explicit user authorization.

App versions are the ASCII dotted integer components immediately after `IDA Professional `; comparison is numeric from left to right, with missing trailing components treated as zero (`9.10 > 9.9`, `10.0 > 9.50`, `9.5 == 9.5.0`). Suffixes after that numeric prefix do not affect ordering. Names without a numeric version rank below numeric versions. Canonical aliases are deduplicated, retaining their highest named version; ties select the lexicographically smallest canonical runtime path.

Before creating a new installation prefix, the selected runtime must pass the existing Python >=3.11, IDA bundle version 9.4/9.5 and exact IDA-provided idapro wheel version/SHA256 checks. Preparation then validates the pinned Nexus/Domain dependency environment and patched modules. A failed selected runtime stops installation; it never silently selects an older candidate. Failed preparation leaves the previous launcher active.

唯一 Nexus 后端在 CLI 发现 daemon 或服务启动前拒绝已删除配置（包括空值）：`IDA_CLI_NEXUS_DEV`、`IDA_CLI_WORKER_BACKEND`、`IDA_CLI_SDK_VERSION`、`IDA_CLI_MAX_WORKERS`、`IDA_CLI_MAX_WORKERS_PER_TENANT`、`IDA_CLI_MAX_PENDING_PER_WORKER`、`IDA_CLI_MAX_CONCURRENT_SPAWNS`。请删除这些变量；按实际需求配置 `IDA_CLI_MAX_PENDING_PER_TENANT`、`IDA_CLI_NEXUS_RETENTION_CAPACITY` 或 `IDA_CLI_HELPER_CAPACITY`。它们是独立限制，不与旧 worker 数量一一对应。

支持的 IDA 运行时集合为 **9.4、9.5**，不接纳低版本或未知新版本。runtime-lock 为每版锁定自带 idapro wheel（9.4: 0.0.9；9.5: 0.0.10）及 SHA256，不跨版本借用。9.4 条目仅在安装后 `__init__.py`、`config.py` 与登记哈希一致时，允许 Domain 0.5.1 要求 idapro>=0.0.10 的这一条元数据冲突；两版运行代码字节相同，Domain 代码支持 IDA >=9.1 且检测新 API。闭包全哈希锁定并以 `--no-deps` 安装，其他 pip check 冲突仍失败。

安装器按应用名称数字版本逐段比较、尾零等价、同版本按规范路径升序选择最新项，打印其他候选；最新不兼容时报错并提示用 `IDADIR` 指定其他候选，不自动退选。启动器保存安装时路径，显式 `IDADIR` 可覆盖到另一受支持版本；probe-runtime/status 分别报告实际 `ida_version` 和 `installed_ida_version`，建议按目标版本重新安装。实际版本由无数据库的有界子进程加载内核核实，并在每次 open 后核对 owner。

N0 固定二进制链接 IDA 9.5，输出对照仅在 9.5 成立。9.4 下需要 N0 的 suite 明确 BLOCKED；contract 可用 `--case E16`、`E17`、`E22` 单独运行。E22 在 9.4 现场生成带标注的旧平铺布局库，核对缓存与预热契约，不宣称 N0 跨版本对照。


RV8-1 的终身保留容量默认是 business **262144**、internal **12582912**（48 倍）、
total **16777216**（64 倍）。`IDA_CLI_NEXUS_RETENTION_CAPACITY` 的正整数覆盖
business 并同比派生其他两项；未设置、非法值或 0 使用默认值。pending 默认仍为 512。
实测 business 墓碑约 **4.5KB/条**，262144 条约 **1.15GB**；请求参数越大占用越多，
这不是内存硬上限，另有 internal 身份、分配器和其他生命周期数据。上限用满后继续拒绝
新预留，必须重启 daemon/bridge 才能恢复；需要覆盖容量时应在重启前配置。
重启不代表可以重放结果未知的请求。


### sBPF code generation profile

Set `IDA_CLI_SBX_PROFILE` before starting the server/daemon. The server reads it;
changing only a client environment does not reconfigure an already running server.
Opening an sBPF `.so` always passes the profile explicitly to `sbx aot i64`:

| Value | sbx arguments |
|---|---|
| unset or `analysis` (default) | `--profile analysis` |
| `analysis-inline` | `--profile analysis --inline` |
| `trace` | `--profile trace` |
| `optimized` | `--profile optimized` (currently refused by sbx for `aot i64`) |

Each profile has its own cache generation. The versioned key records the full raw
BLAKE3 digest and profile in `nexus-index.json` and `generation.json`; old entries
without a profile are never reused. Reopening the same profile uses its generation.
Empty, unknown, or differently cased values fail with `InvalidParams` naming the
variable. sbx failures expose stdout/stderr and never fall back to the raw `.so`.
The existing content lock, input snapshot verification and GC remain in effect.

### Revocable bridge launch authorization

The bridge issues a durable per-launch grant before signing LaunchIntent. A new
SDK worker argument carries its absolute path. Before loading idalib or touching
an IDB, the worker must win an exclusive decision-file creation and durably record
`claimed`. After waitpid of the bridge, the helper may instead win `revoked`.
Both compete for the same `O_EXCL` inode; an incomplete record blocks settlement.
Grant and decision records are retained permanently and never reused. A worker
without this argument keeps the upstream behavior. Legacy launches without a
grant remain pending until their normal public owner lifecycle supplies evidence.
The patched environment must be rebuilt; existing venvs cannot be reused.

### Vendored Nexus source and local patches

`3rd-github/ida-nexus` is the complete, unmodified MIT-licensed tree from
https://github.com/HexRaysSA/ida-nexus, tag `v0.13.4`, commit
`d60ff582fde90c59726336c0dbdf3e8286e9df7a`, tree
`0726da7f22c9354b12184ae40742c65c091ae581` (including upstream dotfiles and LICENSE).
Preparation defaults to this directory, without a Nexus network clone. Release
packages include it; bundle, tag and source-build installs use their bundle's tree.
`--source` (installer: `--nexus-source`) explicitly overrides the input. Both inputs
must match the pinned tree; changed, missing or extra files fail with paths.
Upstream-ignored build products are excluded. Inputs are never modified.
The prepared repository has a deterministic pristine upstream HEAD before the five
patches are applied; its tree ID and upstream commit are recorded in
`environment.json` and `PREPARED`. `source-tree.json` supplies path diagnostics.

```bash
git rev-parse HEAD:3rd-github/ida-nexus
# Compare with the upstream commit's tree in a separate upstream checkout:
git -C "$UPSTREAM" rev-parse 'd60ff582fde90c59726336c0dbdf3e8286e9df7a^{tree}'
```

For DIY, edit the vendor files only while developing the patch, export the diff,
and restore the original vendor tree. Review the patch before adding it to the
preparer and `NEXUS_PATCHES` (also used by CI). Never commit a modified vendor tree.
New files must first be made visible to `git diff` (for example with `git add -N`).

```bash
git diff --relative=3rd-github/ida-nexus -- 3rd-github/ida-nexus > scripts/nexus/local-change.patch
git restore --worktree --staged -- 3rd-github/ida-nexus
# Remove only your own newly created, now-untracked vendor files if applicable.
```

Integrating a patch requires updating the applicable `CANCEL_HANDLE_SHA256` /
`PATCHED_HANDLE_SHA256` in `prepare_nexus_env.py`, `client-sdk-contract.json`
(`files`), and `runtime-lock.json` (`assets`, `installed_files`). A contract change
also changes its asset hash in `runtime-lock.json`. Keep patch checks, intermediate
hashes and installed-module checks; rebuild and run the install/N0/release tests.
`r0_prepare.py` only records the historical three-patch baseline and forwards
pristine source/wheels inputs. It is not a supported current runtime preparer:
the current installed-SDK admission requires `_launch_authorization`, absent from
that baseline, and rejects it explicitly. `r0_sdk_candidate.py --source` instead takes an installed
package to generate its historical candidate and is not a preparer input.

To upgrade, fetch and verify the new upstream tag in a separate checkout, record
commit/tree IDs, and import the complete tree as a dedicated vendor-only commit
(e.g. `git read-tree --prefix=3rd-github/ida-nexus/ -u <tree>` after removing the
old prefix). Update `NEXUS_SHA`, `NEXUS_TREE`, `source-tree.json`, lock/contract
provenance and package version requirements. Rebase all five patches in order,
review their semantics, update all hash gates listed above and rerun the full
acceptance suite including CI client, offline preparation, package installation
and smoke tests. Do not fall back to network sources on verification failure.
