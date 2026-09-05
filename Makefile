export LANG = pl_PL.UTF-8

.PHONY: all fmt check clippy test docker-up docker-down lock unlock run db-reset audit-verify audit-logs rebuild clean init bootstrap setup-all dev dev-down prod unlock-dev bootstrap-dev migrate migrate-dev net-up net-down

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
	docker compose --profile tools build --no-cache kms-ceremony-cli

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

bootstrap:
	MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm -it kms-ceremony-cli import-bootstrap --file ./out/bootstrap-secrets.json.enc --service-url http://kms-service:8080

# --- DEV  ---
unlock-dev:
	MSYS_NO_PATHCONV=1 docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -it vhsm-daemon cargo run -p kms-ceremony-cli -- unseal --threshold 3 --shares-dir ./out/shares --socket-path /run/vhsm/vhsm.sock

bootstrap-dev:
	MSYS_NO_PATHCONV=1 docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm --no-deps kms-ceremony-cli cargo run -p kms-ceremony-cli -- import-bootstrap --file ./out/bootstrap-secrets.json.enc --service-url 'http://kms-service:8080'

# --- PRODUKCJA (używa profilu tools i zbudowanego obrazu) ---
migrate:
	MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm kms-migrate

# --- DEV (używa kompilacji w locie cargo run) ---
migrate-dev:
	MSYS_NO_PATHCONV=1 docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm kms-migrate cargo run -p kms-migrate -- run
	
tools:
	docker compose --profile tools build kms-ceremony-cli

setup-all: unlock bootstrap

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

# Komenda do szybkiego podglądu zaimportowanych zasobów
check-targets:
	docker exec -it $(DB_CONTAINER) psql -U $(DB_USER) -d $(DB_NAME) -c "SELECT id, target_name, target_type, active, created_at FROM target_resources;"

# Komenda do sprawdzenia zaimplementowanych poświadczeń
check-creds:
	docker exec -it $(DB_CONTAINER) psql -U $(DB_USER) -d $(DB_NAME) -c "SELECT id, service_id, target_type, target_db, username, status FROM db_credentials;"

# Uruchomienie z przebudowaniem obrazów (gdy zmieniasz zależności/Dockerfile)
dev-build: net-up
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build

# Szybkie uruchomienie (automatycznie tworzy trwałe sieci, jeśli nie istnieją)
dev: net-up
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up

# Zatrzymanie deweloperskie (czyści wolumeny dev, ale pozostawia trwałe sieci intact)
dev-down:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml down -v
# 	docker compose -f docker-compose.yml -f docker-compose.dev.yml down

# Standardowe uruchomienie produkcyjne
prod: net-up
	docker compose up --build

dev-recreate: net-up
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --force-recreate kms-service