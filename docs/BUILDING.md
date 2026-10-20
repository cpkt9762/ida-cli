# Building from Source

Rust builds need a host Rust toolchain; no IDA SDK, native IDA libraries or LLVM headers are linked. Database execution uses only Nexus. IDA >=9.4, Python >=3.11 and a legally prepared IDA runtime are required for analysis. Missing dependencies and patch mismatches fail explicitly at startup.

```bash
timeout 180s cargo build --locked --release --bin ida-cli
```

Release archives contain the binary, installer, environment preparer, dependency lock, SDK contract and all four patches: loopback-bind, client-cancel-unknown, client-close-proof and client-acquisition. `scripts/nexus/runtime-lock.json` fixes their hashes, Nexus commit, dependency versions and installed module hashes. `scripts/package_release.py` refuses mismatched assets. No IDA proprietary files are distributed.

```bash
python3 scripts/package_release.py --binary target/release/ida-cli --output /tmp/ida-cli-bundle.tar.gz
```

The installer creates a dedicated Python environment under its version directory, installs hashed dependencies, validates the selected IDA-provided idapro wheel, applies the fixed patch chain, verifies the resulting source and actual installed modules, then atomically replaces the launcher. It does not read an IDA profile or accept terms. Set `IDADIR` to the runtime directory before installation; `--bin-dir` and `--install-root` support private installation rehearsals. `--bundle`, `--nexus-source` and `--wheels` accept local read-only inputs. Failed preparation retains the staged version and logs, leaving the previous launcher active.

For a source build, set `IDA_NEXUS_PYTHON` to a prepared environment's absolute `venv/bin/python`. The installed launcher sets this directly. `probe-runtime` performs the same verified Nexus handshake without opening a database; missing/old runtime or incompatible modules return an error. There is no backend selector. Python/native maintenance budgets run in-process and do not require GNU coreutils.

`IDA_CLI_HOME` defaults to `~/.ida` for every frontend. `IDA_NEXUS_IPC_ROOT` optionally chooses a short private parent for bridge endpoints; otherwise the host temporary directory is used. Keep independent home/state/profile/input copies for tests. Offline sbx/idat preparation is retained for sBPF/DSC and never handles ordinary database requests.

Rollback is version-level: retain the fixed N0 executable, matching IDA runtime and closed pre-migration backup. Stop new requests, wait for completion or cancellation evidence, preserve the migrated database, release only owned leases and wait for owner exit before copying. Restore into a separate directory and invoke the old executable directly. Never open a new-runtime database with the old runtime or overwrite real data during rehearsal. Actual installation, daemon restart and rollback require explicit user authorization.
