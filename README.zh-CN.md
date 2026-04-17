# ida-cli

`ida-cli` 是一个面向 macOS / Linux 的无界面 IDA CLI 与 skill-first 工具集。它会在运行时自动选择后端，在需要时自动拉起本地服务，并同时以 flat CLI、stdio MCP、Streamable HTTP MCP 三种方式暴露相同的能力。

[English README](README.md)

## 两个用户入口

- 本地 `ida-cli` 二进制（一个可执行文件同时承担客户端和服务端角色）
- 给 agent 环境安装的 `ida-cli` skill（`skill/SKILL.md`）

底层的 worker / router 服务层由 CLI 自动拉起和回收。只有当你真的需要一个常驻、对外可寻址的服务时，才手动跑 `serve` / `serve-http`。

## 支持矩阵

### 宿主平台

- 支持：macOS、Linux
- 不支持：Windows

### IDA 运行时策略

| IDA 版本 | 后端 | 说明 |
|---|---|---|
| `< 9.0` | 不支持 | — |
| `9.0 – 9.2` | `idat-compat` | 通过 `idat` + IDAPython 兼容 |
| `9.3+` | `native-linked` | 链接 vendored `idalib` 直接进程内打开 |

后端选择由 `probe-runtime` 在运行时决定。编译期仍然需要 IDA SDK，因为 vendored native 层要参与编译；运行时实际加载的 IDA 本体来自 `IDADIR` 或常见安装路径。

## 当前已经可用的能力

在支持的 IDA 9.x 运行时上，`ida-cli` 可以：

- 打开原始 PE / ELF / Mach-O 二进制并复用缓存好的 `.i64`
- 列函数、按名字解析函数、按地址或名字反汇编、Hex-Rays 反编译
- 读取段、字符串、导入、导出、入口点、全局符号
- 地址 ↔ 段 / 函数 / 符号上下文解析
- 读取 bytes / string / int，提供 `read_*` 和 `convert_number` 系列辅助
- 查询地址的 xrefs to/from（包含字符串 xrefs 和结构字段 xrefs）
- 构建 callgraph、basic block、控制流路径
- 搜索文本、立即数、字节、指令、操作数、反编译文本
- 声明 / 应用类型、重命名符号与局部变量、打注释
- 通过 `run_script` 执行 IDAPython 片段

还没对齐的：`idat-compat` 下部分写入 / 高级类型编辑操作仍是部分支持。完整工具清单见 [docs/TOOLS.md](docs/TOOLS.md)。

## 快速开始

### 最推荐路径：直接安装 skill

默认入口是 `ida-cli` skill，而不是手动装 CLI。

```bash
# 查看这个仓库暴露出来的 skill
npx -y skills add https://github.com/cpkt9762/ida-cli --list

# 给 Codex 安装 ida-cli skill
npx -y skills add https://github.com/cpkt9762/ida-cli --skill ida-cli --agent codex --yes --global
```

skill 自带一个 bootstrap wrapper：

```bash
~/.agents/skills/ida-cli/scripts/ida-cli.sh --help
~/.agents/skills/ida-cli/scripts/ida-cli.sh probe-runtime
~/.agents/skills/ida-cli/scripts/ida-cli.sh --path /path/to/binary list-functions --limit 20
```

如果本机没有 `ida-cli`，wrapper 会先跑仓库里的安装脚本再转发命令。

### 直接安装 CLI（可选）

如果你确定要单独使用 CLI，而不是通过 skill：

```bash
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --add-path
```

常见变体：

```bash
# 安装指定版本
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --tag v0.9.3 --add-path

# 直接从分支 / 提交源码构建
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --ref master --build-from-source --add-path
```

说明：

- 安装器默认把 launcher 放到 `~/.local/bin/ida-cli`
- `--add-path` 会把这个目录追加到当前 shell 的 rc 文件
- 如果本地源码构建时没有设置 `IDASDKDIR` / `IDALIB_SDK`，安装器会自动拉取开源 `HexRaysSA/ida-sdk`
- 机器上同时存在多套 IDA 时，建议在安装 / 运行前显式导出 `IDADIR`

### 从源码构建

```bash
git clone https://github.com/cpkt9762/ida-cli.git
cd ida-cli

export IDADIR="/Applications/IDA Professional 9.1.app/Contents/MacOS"   # 或 Linux 安装目录
export IDASDKDIR="/path/to/ida-sdk"                                     # 根目录或 ida-sdk/src 都可

cargo build --bin ida-cli
./target/debug/ida-cli --help
```

### 使用 CLI

`ida-cli` 是 client-first 的：任意客户端子命令都会自动在本地起一个 Streamable HTTP 服务器（随机端口），并通过 `/tmp/ida-cli.socket` 发现真实的 socket：

```bash
./target/debug/ida-cli --path /path/to/sample.bin list-functions --limit 20
./target/debug/ida-cli --path /path/to/sample.bin decompile --addr 0x140001000
./target/debug/ida-cli --path /path/to/sample.bin raw '{"method":"get_xrefs_to","params":{"address":"0x140001000"}}'
```

第一个参数是服务端子命令（`serve` / `serve-http` / `serve-worker` / `probe-runtime`）时，进入服务端模式：

```bash
./target/debug/ida-cli serve                          # stdio MCP
./target/debug/ida-cli serve-http --bind 127.0.0.1:8765
./target/debug/ida-cli probe-runtime
```

后端 probe 的典型输出：

```json
{"runtime":{"major":9,"minor":1,"build":250226},"backend":"idat-compat","supported":true,"reason":null}
```

```json
{"runtime":{"major":9,"minor":3,"build":260213},"backend":"native-linked","supported":true,"reason":null}
```

完整 CLI 使用方式见 [skill/references/cli-tool-reference.md](skill/references/cli-tool-reference.md)。

## 构建要求

- Rust 1.87+
- LLVM / Clang
- macOS 或 Linux 宿主机
- 通过 `IDADIR` 指定 IDA 安装目录（运行时最低要求 IDA 9.0）
- 通过 `IDASDKDIR` 或 `IDALIB_SDK` 指定 IDA SDK

SDK 支持两种布局：

- `/path/to/ida-sdk`
- `/path/to/ida-sdk/src`

## 运行时说明

### `idat-compat`

IDA 9.0–9.2 的兼容后端。通过 `idat` 启动批处理脚本，跑 IDAPython，把结构化 JSON 返回给 CLI 运行时。

### `native-linked`

IDA 9.3+ 的原生后端。直接链接 vendored `idalib` 在进程内打开数据库。

### 缓存和本地运行时路径

- 数据库缓存：`~/.ida/idb/`
- 日志：`~/.ida/logs/server.log`
- 服务 Unix socket：`~/.ida/server.sock`
- 服务 PID 文件：`~/.ida/server.pid`
- CLI 发现文件（把 flat CLI 指到实际 socket）：`/tmp/ida-cli.socket`
- 大响应缓存：`/tmp/ida-cli-out/`

## CI 与发布

GitHub Actions 在 Hosted Runner 上通过开源 `HexRaysSA/ida-sdk` 做编译和测试，不依赖私有机器的固定路径。

当前工作流：

- `master` 上的 push / pull request 跑校验
- 打 tag（例如 `v0.9.3`）构建 Linux / macOS release 资产
- release 同时附带 `install.sh` 和各平台压缩包

release 二进制是用 SDK stub 构建出来的；真正启动时，`install.sh` 生成的 launcher 会优先通过 `IDADIR` 或常见安装路径解析你本机的 IDA 运行时。

## 其他文档

- [docs/BUILDING.md](docs/BUILDING.md) — 源码构建
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — router、后端、federation
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md) — stdio、streamable HTTP、多 IDB
- [docs/TOOLS.md](docs/TOOLS.md) — 自动生成的工具目录
- [docs/TESTING.md](docs/TESTING.md) — 集成与单元测试
- [skill/SKILL.md](skill/SKILL.md) — skill 的 bootstrap 与使用约束
- [skill/references/cli-tool-reference.md](skill/references/cli-tool-reference.md) — 完整 CLI 能力清单

## License

MIT
