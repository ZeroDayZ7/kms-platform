.PHONY: all fmt check clippy test docker-up docker-down

all: fmt check clippy test

fmt:
	cargo fmt --all

check:
	cargo check --workspace --all-targets --all-features

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --workspace --all-targets --all-features

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down -v