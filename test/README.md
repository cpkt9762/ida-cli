# Tests

Integration tests for ida-cli using a minimal `mini.c` fixture.

## Prerequisites

- `curl` (for HTTP tests)

## Build the fixture

```bash
make fixture
```

Compiles `fixtures/mini.c` to `fixtures/mini`. IDA analyzes raw binaries directly on first open.

## Run tests

```bash
make test       # Stdio JSONL test
make test-http  # HTTP/SSE test
```

## Clean

```bash
make clean
```
