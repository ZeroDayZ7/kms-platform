FROM rust:1

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        musl-tools \
        protobuf-compiler \
    && rustup target add x86_64-unknown-linux-musl \
    && rm -rf /var/lib/apt/lists/*

CMD ["/bin/bash", "-lc", "cargo build --release --target x86_64-unknown-linux-musl -p spire-kms-upstream-authority"]
