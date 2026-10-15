.PHONY: build check test smoke gui

build:
	cargo build --workspace
	npm ci --prefix FRAME/webgui
	npm run build --prefix FRAME/webgui

check:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace
	npm test --prefix FRAME/webgui

smoke:
	cargo build -p comb-frame
	python scripts/integration_smoke.py

gui:
	npm run dev --prefix FRAME/webgui
