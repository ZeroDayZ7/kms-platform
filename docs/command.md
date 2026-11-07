docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.spire.yml up -d

docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build

# 1. Nowa gałąź

git switch -c chore/update-dependencies

# 2. Zobacz, co zostanie zaktualizowane

cargo update --dry-run

# 3. Aktualizuj zależności

cargo update

# 4. Formatowanie

cargo fmt --all -- --check

# 5. Testy całego workspace

cargo test --workspace --all-targets

# 6. Kontrola kompilacji

cargo check --workspace --all-targets
