# ida-cli — Headless IDA CLI and MCP server

# Show available recipes
default:
    @just --list

# Build debug binary
build:
    cargo build

# Build release binary
release:
    cargo build --release

# Run integration test (debug)
test: build
    cd test && SERVER_BIN=../target/debug/ida-cli RUST_LOG=ida_mcp=trace just test

# Run HTTP integration test (debug)
test-http: build
    cd test && SERVER_BIN=../target/debug/ida-cli RUST_LOG=ida_mcp=trace just test-http

# Run IDAPython script integration test (debug)
test-script: build
    cd test && SERVER_BIN=../target/debug/ida-cli RUST_LOG=ida_mcp=trace just test-script

# Run cargo unit tests
cargo-test:
    RUST_BACKTRACE=1 cargo test

# Format code
fmt:
    cargo fmt --all

# Run clippy linter
lint:
    cargo clippy -- -D warnings

# Run full check (fmt + lint + test)
check: fmt lint cargo-test

# Clean build artifacts
clean:
    cargo clean
    rm -rf dist/

# Bump version and push tag
bump:
    git tag $(svu patch)
    git push --tags
