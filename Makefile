PREFIX      ?= $(HOME)/.skillshub/ida
BINDIR      := $(PREFIX)/bin
CARGO       := cargo
RELEASE_DIR := $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)/release
BIN_NAME    := ida-cli
CLI_NAME    := ida-cli

.PHONY: build install uninstall clean test lint fmt check

build:
	timeout 180s $(CARGO) build --release --locked

install: build
	@stage=$$(mktemp -d); \
	python3 scripts/package_release.py --binary $(RELEASE_DIR)/$(BIN_NAME) --output $$stage/bundle.tar.gz && \
	tar -xzf $$stage/bundle.tar.gz -C $$stage && \
	bash scripts/install.sh --bundle $$stage --bin-dir $(BINDIR) --install-root $(PREFIX)/lib/ida-cli; \
	result=$$?; rm -rf $$stage; exit $$result

uninstall:
	rm -f $(BINDIR)/$(CLI_NAME) $(BINDIR)/sbpf2host
	@echo "Removed from $(BINDIR)/"

clean:
	timeout 30s $(CARGO) clean

test:
	timeout 120s $(CARGO) test --locked --lib

lint:
	timeout 30s $(CARGO) clippy --locked --all-targets -- -D warnings

fmt:
	timeout 30s $(CARGO) fmt --all

check: fmt lint test
