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

sqlc generate

# ================================================================

docker compose down -v
docker compose build --no-cache
docker compose up -d

docker compose down -v && docker compose up --build --force-recreate -d

# ============================ -it ================================

MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm -it kms-ceremony-cli interactive --socket-path /run/vhsm/vhsm.sock

MSYS_NO_PATHCONV=1 docker compose --profile tools run --rm -it kms-ceremony-cli unseal --threshold 3 --shares-dir ./out/shares --socket-path /run/vhsm/vhsm.sock
