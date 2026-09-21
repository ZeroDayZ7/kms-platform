docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.spire.yml up -d

docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build

docker compose -f docker-compose.yml -f docker-compose.spire.yml up --build -d

docker compose -f docker-compose.yml -f docker-compose.spire.yml up -d

docker network create kms_internal_net
docker network create kms_sec_net
docker network create kms_target_admin_net

docker compose -f docker-compose.yml -f docker-compose.spire.yml down
rm -rf spire/server/data/\*

docker volume rm \
 kms_service_spire-agent-data \
 kms_service_spire-agent-socket \
 kms_service_spire-agent-token \
 kms_service_spire-bundle \
 kms_service_spire-server-data \
 kms_service_spire-server-socket

docker compose -f docker-compose.yml -f docker-compose.spire.yml up -d
