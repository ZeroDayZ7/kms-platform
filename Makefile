export LANG = pl_PL.UTF-8

.PHONY: all fmt check clippy test docker-up docker-down lock unlock run db-reset audit-verify audit-logs rebuild clean

all: fmt check clippy test

fcc: fmt check clippy

fmt:
	cargo fmt --all

check:
	cargo check --workspace --all-targets --all-features

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --workspace --all-targets --all-features

docker-up:
	docker compose up -d

docker-down:
	docker compose down -v

clean:
	cargo clean

rebuild:
	@echo "===> Czyszczenie starych kontenerów i wolumenów..."
	docker compose down -v --remove-orphans
	@echo "===> Generowanie kodu SQL (sqlc)..."
	sqlc generate -f crates/kms-service/sqlc.yaml
	@echo "===> Formatowanie kodu (cargo fmt)..."
	cargo fmt
	@echo "===> Budowanie obrazów bez cache..."
	docker compose build --no-cache
	@echo "===> Uruchamianie środowiska..."
	docker compose up -d
	@echo "===> Śledzenie logów migratora..."
	docker compose logs -f kms-migrate

init:
	MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm -it kms-ceremony-cli interactive --socket-path /run/vhsm/vhsm.sock

unlock:
	MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm -it kms-ceremony-cli unseal --threshold 3 --shares-dir ./out/shares --socket-path /run/vhsm/vhsm.sock

audit-verify:
	MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm kms-ceremony-cli verify-audit-chain

audit-logs:
	MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm kms-ceremony-cli audit-logs

run:
	cargo run -p kms-service --bin kms-service -- serve

db-reset:
	docker compose stop postgres kms-service vhsm-daemon
	docker compose rm -f postgres
	-docker volume rm $$(docker volume ls -q -f name=postgres_data)
	docker compose up -d