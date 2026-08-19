# ==============================================================================
# STAGE 1: Cargo Chef Installation
# ==============================================================================
FROM rust:1.97-slim-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

# ==============================================================================
# STAGE 2: Recipe Planner (Generowanie przepisu na zależności)
# ==============================================================================
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ==============================================================================
# STAGE 3: Dependency Builder (Kompilacja i cache zależności)
# ==============================================================================
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

# Wymagane pakiety do kompilacji (np. OpenSSL / PKG-Config)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Kompilujemy TYLKO zależności — ten krok jest cache'owany przez Dockera!
RUN cargo chef cook --release --recipe-path recipe.json

# Kopiujemy kod źródłowy projektu i budujemy właściwą binarkę
COPY . .
RUN cargo build --release --bin kms-service

# ==============================================================================
# STAGE 4: Final Production Runtime (Non-Root, Minimal)
# ==============================================================================
FROM debian:bookworm-slim AS runtime

# 1. Tworzymy użytkownika i grupę aplikacyjną bez uprawnień root (UID/GID 10001)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

# 2. Instalujemy niezbędne biblioteki uruchomieniowe
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 3. Kopiujemy ze stadiów budowania wyłącznie gotową binarkę
COPY --from=builder /app/target/release/kms-service /app/kms-service

# 4. Nadajemy uprawnienia i przełączamy na nieuprzywilejowanego użytkownika
RUN chown -R appuser:appgroup /app
USER appuser:appgroup

ENV RUST_LOG=info \
    APP_ENVIRONMENT=production

EXPOSE 8080

ENTRYPOINT ["/app/kms-service"]