docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.spire.yml up -d

docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
