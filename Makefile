export LANG = pl_PL.UTF-8

.PHONY: all fmt check clippy test docker-up docker-down lock unlock run db-reset audit-verify audit-logs rebuild clean init bootstrap setup-all dev dev-down prod unlock-dev bootstrap-dev migrate migrate-dev net-up net-down ca-init ca-init-dev ca-load ca-load-dev setup-dev

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

# --- ZARZĄDZANIE SIECIAMI (STALE SIECI) ---
net-up:
	@docker network create kms_internal_net 2>/dev/null || true
	@docker network create kms_sec_net 2>/dev/null || true
	@docker network create kms_target_admin_net 2>/dev/null || true

net-down:
	@docker network rm kms_internal_net 2>/dev/null || true
	@docker network rm kms_sec_net 2>/dev/null || true
	@docker network rm kms_target_admin_net 2>/dev/null || true

docker-down:
	docker compose down -v

docker-up: net-up
	docker compose up -d

docker-rebuild: net-up
	docker compose down -v
	docker compose up -d --build --force-recreate

profile:
	docker compose --profile tools build kms-ceremony-cli

clean:
	cargo clean

rebuild: net-up
	@echo "===> Czyszczenie starych kontenerów i wolumenów..."
	docker compose --profile tools down -v --remove-orphans
	@echo "===> Formatowanie kodu (cargo fmt)..."
	cargo fmt
	@echo "===> Budowanie wszystkich obrazów (w tym tools) bez cache..."
	docker compose --profile tools build --no-cache
	@echo "===> Uruchamianie środowiska..."
	docker compose --profile tools up -d
	@echo "===> Śledzenie logów migratora..."
	docker compose logs -f kms-migrate

init:
	MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm -it kms-ceremony-cli interactive --socket-path /run/vhsm/vhsm.sock

# --- PRODUKCJA ---
unlock:
	MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm -it kms-ceremony-cli unseal --threshold 3 --shares-dir ./out/shares --socket-path /run/vhsm/vhsm.sock

ca-init:
	MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm -it kms-ceremony-cli ca-init --socket-path /run/vhsm/vhsm.sock --ca-tag root

ca-load:
	MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm -it kms-ceremony-cli ca-load --socket-path /run/vhsm/vhsm.sock --ca-tag root --encrypted-b64 "$(ENCRYPTED_B64)"

bootstrap:
	MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm -it kms-ceremony-cli import-bootstrap --file ./out/bootstrap-secrets.json.enc --service-url http://kms-service:8080

setup-all: unlock ca-init bootstrap

# --- DEV ---
unlock-dev:
	MSYS_NO_PATHCONV=1 docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -it vhsm-daemon cargo run -p kms-ceremony-cli -- unseal --threshold 3 --shares-dir ./out/shares --socket-path /run/vhsm/vhsm.sock

ca-init-dev:
	MSYS_NO_PATHCONV=1 docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm --env-file .env --no-deps kms-ceremony-cli cargo run -p kms-ceremony-cli -- ca-init --socket-path /run/vhsm/vhsm.sock --ca-tag root

ca-load-dev:
	MSYS_NO_PATHCONV=1 docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm --env-file .env --no-deps kms-ceremony-cli cargo run -p kms-ceremony-cli -- ca-load --socket-path /run/vhsm/vhsm.sock --ca-tag root --encrypted-b64 "$(ENCRYPTED_B64)"

bootstrap-dev:
	MSYS_NO_PATHCONV=1 docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm --no-deps kms-ceremony-cli cargo run -p kms-ceremony-cli -- import-bootstrap --file ./out/bootstrap-secrets.json.enc --service-url 'http://kms-service:8080'

setup-dev: unlock-dev ca-init-dev bootstrap-dev

# --- MIGRACJE ---
migrate:
	MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm kms-migrate

migrate-dev:
	MSYS_NO_PATHCONV=1 docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm kms-migrate cargo run -p kms-migrate -- run

tools:
	docker compose --profile tools build kms-ceremony-cli

audit-verify:
	MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm kms-ceremony-cli verify-audit-chain

audit-logs:
	MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm kms-ceremony-cli audit-logs

db-reset:
	docker compose stop postgres kms-service vhsm-daemon
	docker compose rm -f postgres
	-docker volume ls -q -f name=postgres_data | xargs -r docker volume rm
	docker compose up -d

# Domyślne wartości zmiennych
DB_CONTAINER ?= db_kms
DB_USER      ?= kms_root_user
DB_NAME      ?= kms_db

check-targets:
	docker exec -it $(DB_CONTAINER) psql -U $(DB_USER) -d $(DB_NAME) -c "SELECT id, target_name, target_type, active, created_at FROM target_resources;"

check-creds:
	docker exec -it $(DB_CONTAINER) psql -U $(DB_USER) -d $(DB_NAME) -c "SELECT id, service_id, target_type, target_db, username, status FROM db_credentials;"

dev-build: net-up
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build

dev: net-up
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d

dev-down:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml down -v

prod: net-up
	docker compose up --build

dev-recreate: net-up
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --force-recreate kms-service