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

运行时要求 IDA >=9.4、Python >=3.11。所有数据库操作统一通过固定 Nexus 0.13.4 / Domain 0.5.1 专用环境执行；依赖或补丁不匹配直接报错。Rust 构建不需要 IDA SDK。

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

完整工具统一使用 Nexus；运行时缺失能力会明确报错。完整工具清单见 [docs/TOOLS.md](docs/TOOLS.md)。

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
- 安装器创建专用 Nexus Python 环境，并校验四个本地补丁、依赖与已安装模块的 SHA256。
- macOS 安装器和启动器会检测 `/Applications` 与 `~/Applications`：唯一安装自动使用，多个或没有候选时列出路径并要求设置 `IDADIR`。显式 `IDADIR` 优先，支持 `.app`、`Contents` 或运行时目录。

### 从源码构建

```bash
git clone https://github.com/cpkt9762/ida-cli.git
cd ida-cli

export IDADIR="/Applications/IDA Professional 9.5.app/Contents/MacOS"   # 或 Linux 安装目录

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

查看 daemon 当前打开了哪些数据库、由哪些客户端持有，用 `list-idbs`（MCP 工具：`list_idbs`）。
重建或替换 `.i64`（例如用 `idat`）之前先跑一次：仍出现在列表里的库就是被 daemon 持有的，
`idat` 对已在别处打开的库会失败。返回 `{"count": N, "idbs": [...]}`，每项包含 `db_handle`、
输入文件与 `.i64` 路径、打开它的客户端的不可逆标识、打开时间、所在 worker、是否为活动库，
以及仍持有引用的客户端。不会返回 `close_token`。

```bash
./target/debug/ida-cli list-idbs --json
```

需要每一行伪代码对应的地址时，给 `decompile` 加 `--line-addresses`（MCP / RPC：`decompile_function` 的
`line_addresses: true`）。返回变为 `{"code": ..., "lines": [...]}`：`code` 与平时相同，`lines` 每项是
`{"line", "text", "addresses"}`。`line` 从 1 开始，`text` 是 `code` 里的同一行，`addresses` 是 Hex-Rays
挂在这一行上的 ctree 项的 IDA 地址（十六进制字符串，升序、去重）。一行可能对应多个不连续的地址，
列表也不是该语句的全部指令；函数签名和局部变量声明没有地址；`{`、`}`、`else` 和空行可能带着所属块或
`if` 的地址（最外层大括号是函数入口）。该模式不加 `sub_` 改名提示。Hex-Rays 对很大的函数，
两次调用打印出的文本可能不同，所以 `code` 与 `lines` 只能取自同一次应答。Nexus 支持该模式。经 CLI socket 时，大结果与其他命令一样落到响应缓存
（`IDA_MCP_MAX_INLINE_BYTES`）。

```json
{"line": 6, "text": "  while ( a1 != 1 )", "addresses": ["0x10000033c", "0x100000340"]}
```

第一个参数是服务端子命令（`serve` / `serve-http` / `serve-worker` / `probe-runtime`）时，进入服务端模式：

```bash
./target/debug/ida-cli serve                          # stdio MCP
./target/debug/ida-cli serve-http --bind 127.0.0.1:8765
./target/debug/ida-cli probe-runtime
```

`probe-runtime` 检查唯一 Nexus 后端的依赖、补丁及协议握手，失败时退出非零。

完整 CLI 使用方式见 [skill/references/cli-tool-reference.md](skill/references/cli-tool-reference.md)。

## 构建要求

- Rust 1.87+
- macOS 或 Linux 宿主机
- 通过 `IDADIR` 指定 IDA 安装目录（运行时最低要求 IDA 9.4）

## 运行时说明

### Nexus

安装器直接定位专用 Python 环境；源码运行可设置 `IDA_NEXUS_PYTHON`。离线 sBPF/DSC 准备仍使用 sbx/idat，普通查询、编辑与数据库会话只走 Nexus。回退使用固定 N0 旧发行二进制和迁移前的已关闭备份，在独立恢复目录操作，不能切换运行时后端。真实环境安装/切回仍需明确授权。

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

release 二进制不链接 IDA 库；安装器创建并直接定位固定、带四补丁的 Nexus Python 环境。

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
