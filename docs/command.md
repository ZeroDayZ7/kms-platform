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

cargo fmt --all
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features

curl -X GET http://localhost:8080/status

cargo run -- generate -s 5 -t 3 -o ./out
cargo run recover --shares-dir ./out/shares --output-key ./recovered.key

kms-ceremony-cli generate --shares 5 --threshold 3 --output-dir ./out
kms-ceremony-cli recover --shares-dir ./out/shares --output-key ./recovered.key
