.PHONY: build check test smoke gui install-smoke browser-smoke https-browser-smoke ssh-smoke

# Bound each test phase, including subprocesses; override for slower CI hosts.
TEST_TIMEOUT ?= 180s

build:
	cargo build --workspace
	npm ci --prefix FRAME/webgui
	npm run build --prefix FRAME/webgui

check:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings

test:
	timeout --kill-after=5s $(TEST_TIMEOUT) cargo test --workspace
	timeout --kill-after=5s $(TEST_TIMEOUT) npm test --prefix FRAME/webgui
	timeout --kill-after=5s $(TEST_TIMEOUT) python scripts/test_install.py

smoke:
	cargo build -p comb-frame
	python scripts/integration_smoke.py
	python scripts/managed_walkthrough_smoke.py

install-smoke:
	python scripts/installed_service_smoke.py

gui:
	npm run dev --prefix FRAME/webgui

browser-smoke: build
	node scripts/webgui_browser_smoke.mjs

# OpenSSL and NSS certutil establish isolated test trust; no browser TLS bypass.
https-browser-smoke: build
	timeout --kill-after=5s $(TEST_TIMEOUT) node scripts/https_browser_smoke.mjs

ssh-smoke:
	cargo build -p comb-frame
	timeout --kill-after=5s $(TEST_TIMEOUT) python scripts/ssh_setup_smoke.py
