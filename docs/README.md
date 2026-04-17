# Documentation

ida-cli is a headless IDA Pro MCP server with a discovery-first tool model.

## Design

- **Full tool list by default** - Supports MCP clients that only register tools at connection time
- **Tool discovery** - Use `tool_catalog` to find tools, `tool_help` for docs
- **Streamable HTTP** - Multi-client support with streaming notifications
- **Serialized IDA access** - All IDA work runs through a single worker thread

## Contents

- [TOOLS.md](TOOLS.md) - Tool catalog and discovery workflow
- [TRANSPORTS.md](TRANSPORTS.md) - Stdio vs Streamable HTTP
- [BUILDING.md](BUILDING.md) - Build from source
- [TESTING.md](TESTING.md) - Running tests
