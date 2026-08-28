# STAGE 1: Chef Base
FROM lukemathwalker/cargo-chef:latest-rust-1-slim-bookworm AS chef
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# STAGE 2: Planner
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# STAGE 3: Builder
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release -p kms-ceremony-cli -p kms-service -p kms-migrate -p vhsm-daemon

# STAGE 4: Base Runtime
FROM debian:bookworm-slim AS runtime-base
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# ------------------------------------------------------------------------------
# TARGET 1: vhsm-daemon
# ------------------------------------------------------------------------------
FROM runtime-base AS vhsm-daemon
COPY --from=builder /app/target/release/vhsm-daemon /app/vhsm-daemon
COPY --from=builder /app/target/release/hsm_probe /app/hsm_probe
RUN mkdir -p /run/vhsm && \
    chown -R appuser:appgroup /run/vhsm && \
    chmod 770 /run/vhsm
RUN chown -R appuser:appgroup /app
USER appuser:appgroup
ENV RUST_LOG=info APP_ENVIRONMENT=production
ENTRYPOINT ["/app/vhsm-daemon"]

# ------------------------------------------------------------------------------
# TARGET 2: kms-service
# ------------------------------------------------------------------------------
FROM runtime-base AS kms-service
COPY --from=builder /app/target/release/kms-service /app/kms-service
RUN mkdir -p /app/config /app/ceremony && \
    chown -R appuser:appgroup /app
USER appuser:appgroup
ENV RUST_LOG=info APP_ENVIRONMENT=production
EXPOSE 8080
ENTRYPOINT ["/app/kms-service"]

# ------------------------------------------------------------------------------
# TARGET 3: kms-ceremony-cli
# ------------------------------------------------------------------------------
FROM runtime-base AS kms-ceremony-cli
COPY --from=builder /app/target/release/kms-ceremony-cli /app/kms-ceremony-cli
RUN mkdir -p /app/ceremony && \
    chown -R appuser:appgroup /app
USER appuser:appgroup
ENV RUST_LOG=info
ENTRYPOINT ["/app/kms-ceremony-cli"]