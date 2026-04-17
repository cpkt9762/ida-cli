# ida-cli

`ida-cli` 是一个无界面的 IDA CLI / MCP 服务端，支持根据运行时自动选择后端。

[English README](README.md)

## 概览

`ida-cli` 提供三种使用方式：

- 通过 Unix Socket 的本地 CLI
- 通过 stdio 的 MCP
- 通过 Streamable HTTP 的 MCP

当前有两类运行时后端：

- `native-linked`
  直接使用 vendored `idalib`，适用于能够安全 in-process 打开数据库的较新运行时。
- `idat-compat`
  使用 `idat` + IDAPython 做兼容层，专门处理旧运行时上 `open_database_quiet()` 会崩溃的问题。

在当前分支里，像本机实测的 IDA 9.1 这类旧 9.x 运行时，会自动切到 `idat-compat`。

## 当前已经可用的能力

在实测的本机 IDA 9.1 环境中，`ida-cli` 已经可以：

- 打开原始二进制并复用缓存数据库
- 列函数、按名字解析函数
- 按地址或函数反汇编
- 反编译函数
- 读取地址信息、段、字符串、导入、导出、入口点、全局符号
- 读取 bytes / string / int
- 查询地址的 xrefs to / from
- 搜索文本和字节模式
- 执行 IDAPython 代码

样本 `/Users/gmh/code/devmp/example2-devirt.bin` 已完成端到端验证：

- `list-functions` 找到 `main`，地址 `0x140001000`
- `decompile --addr 0x140001000` 成功

目前还没有做到的是 `idat-compat` 下的全部写操作和复杂类型编辑完全对齐。

## 快速开始

### 启动服务

```bash
export IDADIR="/Applications/IDA Professional 9.1.app/Contents/MacOS"
export IDASDKDIR=/tmp/ida-sdk-sdk3

cargo build --bin ida-cli
./target/debug/ida-cli serve
```

### 使用 CLI

```bash
./target/debug/ida-cli --path /Users/gmh/code/devmp/example2-devirt.bin list-functions --limit 20
./target/debug/ida-cli --path /Users/gmh/code/devmp/example2-devirt.bin decompile --addr 0x140001000
./target/debug/ida-cli --path /Users/gmh/code/devmp/example2-devirt.bin raw '{"method":"get_xrefs_to","params":{"path":"/Users/gmh/code/devmp/example2-devirt.bin","address":"0x140001000"}}'
```

### 查看运行时选中的后端

```bash
./target/debug/ida-cli probe-runtime
```

在当前 9.1 环境中的示例输出：

```json
{"runtime":{"major":9,"minor":0,"build":250226},"backend":"idat-compat","supported":true,"reason":null}
```

## 构建要求

- Rust 1.77+
- LLVM/Clang
- 通过 `IDADIR` 指定 IDA 安装目录
- 通过 `IDASDKDIR` 或 `IDALIB_SDK` 指定 IDA SDK

SDK 路径支持两种布局：

- `/path/to/ida-sdk`
- `/path/to/ida-sdk/src`

## 运行时说明

### `native-linked`

这是较新的原生后端，直接链接 vendored `idalib`。

### `idat-compat`

这是旧运行时兼容后端。它通过 `idat` 启动批处理脚本，跑 IDAPython，把结构化结果返回给 router。这样可以避开旧运行时上会直接把 worker 打崩的原生开库路径。

### 缓存和路径

- 数据库缓存：`~/.ida/idb/`
- 日志：`~/.ida/logs/server.log`
- CLI 发现 socket：`/tmp/ida-cli.socket`
- 大响应缓存：`/tmp/ida-cli-out/`

## 其他文档

- [docs/BUILDING.md](docs/BUILDING.md)
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md)
- [docs/TOOLS.md](docs/TOOLS.md)

## License

MIT
