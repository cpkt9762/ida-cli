# Documentation

`ida-cli` is a CLI-first headless IDA Pro toolkit with an installable skill
and an auto-managed local runtime.

## Design

- **CLI-first workflow** — the default user path is `ida-cli`, not a
  specific transport protocol.
- **Skill-first bootstrap** — the `ida-cli` skill can install and verify
  the CLI automatically.
- **Auto-managed local runtime** — normal use does not require starting a
  server by hand; any client subcommand auto-starts one when needed.
- **Serialised IDA access** — all IDA work for a given database still runs
  through a single worker subprocess, one per open database.

## Contents

- [BUILDING.md](BUILDING.md) — build from source
- [ARCHITECTURE.md](ARCHITECTURE.md) — router, backends, federation
- [TRANSPORTS.md](TRANSPORTS.md) — stdio, streamable HTTP, multi-IDB
- [TOOLS.md](TOOLS.md) — auto-generated tool catalog
- [TESTING.md](TESTING.md) — running integration and unit tests
- [MULTI_IDB.md](MULTI_IDB.md) — multi-IDB router notes
- [UPGRADE_PLAN.md](UPGRADE_PLAN.md) — upgrade plan for larger deployments

The skill sits under [`../skill/`](../skill/). Its main entrypoint is
[`SKILL.md`](../skill/SKILL.md), and the most actionable quick reference is
[`cli-tool-reference.md`](../skill/references/cli-tool-reference.md).
