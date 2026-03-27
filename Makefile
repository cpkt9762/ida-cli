PREFIX      ?= $(HOME)/.skillshub/ida
BINDIR      := $(PREFIX)/bin
CARGO       := cargo
RELEASE_DIR := target/release
BIN_NAME    := ida-mcp
CLI_NAME    := ida-cli

.PHONY: build install uninstall clean test lint fmt check

build:
	$(CARGO) build --release

install: build
	@mkdir -p $(BINDIR)
	cp $(RELEASE_DIR)/$(BIN_NAME) $(BINDIR)/$(CLI_NAME)
	@# sbpf2host: copy from known locations if available
	@for src in $(HOME)/.local/bin/sbpf2host $(HOME)/.cargo/bin/sbpf2host; do \
		if [ -x "$$src" ]; then \
			cp "$$src" $(BINDIR)/sbpf2host; \
			break; \
		fi; \
	done
	@# macOS: ad-hoc sign to avoid quarantine kills
	@if [ "$$(uname)" = "Darwin" ]; then \
		codesign -s - $(BINDIR)/$(CLI_NAME) 2>/dev/null || true; \
		[ -f $(BINDIR)/sbpf2host ] && codesign -s - $(BINDIR)/sbpf2host 2>/dev/null || true; \
	fi
	@echo ""
	@echo "Installed to $(BINDIR)/"
	@ls -lh $(BINDIR)/
	@echo ""
	@echo "Usage:  $(BINDIR)/$(CLI_NAME) cli --path <file> list-functions --limit 20"

uninstall:
	rm -f $(BINDIR)/$(CLI_NAME) $(BINDIR)/sbpf2host
	@echo "Removed from $(BINDIR)/"

clean:
	$(CARGO) clean

test:
	$(CARGO) test --lib

lint:
	$(CARGO) clippy -- -D warnings

fmt:
	$(CARGO) fmt --all

check: fmt lint test
