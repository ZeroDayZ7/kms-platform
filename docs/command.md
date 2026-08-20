cargo fmt
cargo fmt --check
cargo check
cargo check --all-targets --all-features
cargo clippy
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test --all-targets --all-features
key_pairs
cargo run
cargo run -- serve
cargo build --release
cargo build --release -p vhsm-daemon

# Buduje wszystkie serwisy produkcyjne (mongodb, redis, vhsm-daemon, kms-service)

docker compose build
docker compose up --build -d

# Buduje wszystkie serwisy łącznie z narzędziami CLI (kms-ceremony-cli)

docker compose --profile tools build

# Uruchamia główne usługi w tle (MongoDB, Redis, vHSM Daemon, KMS Service)

docker compose down -v
docker compose up -d

# Jeśli chcesz uruchomić również narzędzia (np. kms-ceremony-cli)

docker compose --profile tools run --rm kms-ceremony-cli
MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm kms-ceremony-cli interactive --socket-path /run/vhsm/vhsm.sock

docker compose --profile tools up -d

docker compose build vhsm-daemon
docker compose up -d vhsm-daemon

docker compose --profile tools build kms-ceremony-cli
docker compose --profile tools run --rm kms-ceremony-cli
