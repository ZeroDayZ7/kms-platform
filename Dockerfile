# ==============================================================================
# STAGE 1: Cargo Chef Base (Gotowe środowisko z cargo-chef i zależnościami C)
# ==============================================================================
FROM lukemathwalker/cargo-chef:latest-rust-1-slim-bookworm AS chef
WORKDIR /app

# Instalujemy zależności systemowe potrzebne do budowania skrzynek i ich zależności C
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# ==============================================================================
# STAGE 2: Recipe Planner (Generowanie przepisu na zależności dla workspace)
# ==============================================================================
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ==============================================================================
# STAGE 3: Dependency Builder (Kompilacja i cache zależności całego workspace)
# ==============================================================================
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

# Kompilujemy TYLKO zależności workspace — ten krok trafia do cache'a Dockera!
RUN cargo chef cook --release --recipe-path recipe.json

# Kopiujemy kod źródłowy projektu i budujemy pliki binarne
COPY . .
RUN cargo build --release -p kms-service \
    && cargo build --release -p vhsm-daemon \
    && cargo build --release -p kms-ceremony-cli

# ==============================================================================
# STAGE 4: Final Production Runtime (Non-Root, Minimal)
# ==============================================================================
FROM debian:bookworm-slim AS runtime

# 1. Tworzymy użytkownika i grupę aplikacyjną bez uprawnień root (UID/GID 10001)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

# 2. Instalujemy niezbędne biblioteki uruchomieniowe (curl jest potrzebny do healthchecków)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 3. Kopiujemy ze stadiów budowania gotowe binarki workspace'a
COPY --from=builder /app/target/release/kms-service /app/kms-service
COPY --from=builder /app/target/release/vhsm-daemon /app/vhsm-daemon
COPY --from=builder /app/target/release/kms-ceremony-cli /app/kms-ceremony-cli

# 4. Nadajemy uprawnienia do katalogu roboczego
RUN chown -R appuser:appgroup /app

# Przełączamy na użytkownika nieuprzywilejowanego
USER appuser:appgroup

ENV RUST_LOG=info \
    APP_ENVIRONMENT=production

EXPOSE 8080

ENTRYPOINT ["/app/kms-service"]