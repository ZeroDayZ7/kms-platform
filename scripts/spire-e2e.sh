#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export SPIRE_TRUST_DOMAIN="${SPIRE_TRUST_DOMAIN:-example.org}"
export SPIRE_SERVER_PORT="${SPIRE_SERVER_PORT:-8081}"
export SPIRE_JOIN_TOKEN="${SPIRE_JOIN_TOKEN:-spire-join-token}"

mkdir -p "$ROOT_DIR/spire/server" "$ROOT_DIR/spire/agent" "$ROOT_DIR/spire/entries"

cat > "$ROOT_DIR/spire/server/server.conf" <<EOF
server {
    bind_address = "0.0.0.0"
    bind_port = "${SPIRE_SERVER_PORT}"
    socket_path = "/tmp/spire-server/private/api.sock"
    trust_domain = "${SPIRE_TRUST_DOMAIN}"
    data_dir = "/run/spire/data"
    log_level = "DEBUG"
    ca_subject = {
      country = ["US"]
      organization = ["SPIRE Lab"]
      common_name = "${SPIRE_TRUST_DOMAIN}"
    }
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "/run/spire/data/datastore.sqlite3"
        }
    }

    KeyManager "disk" {
        plugin_data {
            keys_path = "/run/spire/data/keys.json"
        }
    }

    NodeAttestor "join_token" {
        plugin_data {}
    }

    NodeResolver "noop" {
        plugin_data {}
    }

    Notifier "noop" {
        plugin_data {}
    }
}
EOF

cat > "$ROOT_DIR/spire/agent/agent.conf" <<EOF
agent {
    data_dir = "/run/spire/data"
    log_level = "DEBUG"
    server_address = "spire-server"
    server_port = "${SPIRE_SERVER_PORT}"
    socket_path = "/tmp/spire-agent.sock"
    trust_bundle_path = "/run/spire/data/bundle.crt"
    trust_domain = "${SPIRE_TRUST_DOMAIN}"
    admin_socket_path = "/tmp/spire-agent-admin.sock"
}

plugins {
    NodeAttestor "join_token" {
        plugin_data {
            join_token = "${SPIRE_JOIN_TOKEN}"
        }
    }

    KeyManager "disk" {
        plugin_data {
            keys_path = "/run/spire/data/keys.json"
        }
    }

    WorkloadAttestor "unix" {
        plugin_data {
            discover_workload_path = true
        }
    }
}
EOF

cat > "$ROOT_DIR/spire/entries/kms-registration.json" <<EOF
{
  "spiffe_id": "spiffe://${SPIRE_TRUST_DOMAIN}/kms",
  "parent_id": "spiffe://${SPIRE_TRUST_DOMAIN}/spire/server",
  "selectors": [
    "unix:uid:0"
  ],
  "ttl": 3600
}
EOF

cat > "$ROOT_DIR/spire/entries/test-client-registration.json" <<EOF
{
  "spiffe_id": "spiffe://${SPIRE_TRUST_DOMAIN}/test-client",
  "parent_id": "spiffe://${SPIRE_TRUST_DOMAIN}/spire/server",
  "selectors": [
    "unix:uid:0"
  ],
  "ttl": 3600
}
EOF

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is required to run the SPIRE lab but is not installed or reachable in this environment." >&2
  exit 127
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: Docker Compose is not available in this environment." >&2
  exit 127
fi

printf '\n==> Validating compose file\n'
docker compose -f "$ROOT_DIR/docker-compose.spire.yml" config >/tmp/spire-compose-config.txt
cat /tmp/spire-compose-config.txt

printf '\n==> Starting SPIRE server\n'
docker compose -f "$ROOT_DIR/docker-compose.spire.yml" up -d spire-server

docker compose -f "$ROOT_DIR/docker-compose.spire.yml" exec -T spire-server /usr/local/bin/spire-server entry create \
  -spiffeID "spiffe://${SPIRE_TRUST_DOMAIN}/kms" \
  -parentID "spiffe://${SPIRE_TRUST_DOMAIN}/spire/server" \
  -selector "unix:uid:0"

docker compose -f "$ROOT_DIR/docker-compose.spire.yml" exec -T spire-server /usr/local/bin/spire-server entry create \
  -spiffeID "spiffe://${SPIRE_TRUST_DOMAIN}/test-client" \
  -parentID "spiffe://${SPIRE_TRUST_DOMAIN}/spire/server" \
  -selector "unix:uid:0"

printf '\n==> Starting SPIRE agent\n'
docker compose -f "$ROOT_DIR/docker-compose.spire.yml" up -d spire-agent

printf '\n==> Fetching client SVID from SPIRE Workload API\n'
docker compose -f "$ROOT_DIR/docker-compose.spire.yml" run --rm test-client sh -c '
  mkdir -p /tmp/spire-test-client && \
  /usr/local/bin/spire-agent api fetch x509 -socketPath /tmp/spire-agent.sock -write /tmp/spire-test-client && \
  ls -l /tmp/spire-test-client && \
  echo "TEST_CLIENT_SPIFFE=$(openssl x509 -in /tmp/spire-test-client/svid.pem -noout -text | grep -A1 "Subject Alternative Name" | tail -n +2 | tr -d " " | tr "," "\n" | grep "spiffe://" | head -n 1)"'

printf '\n==> Starting KMS\n'
docker compose -f "$ROOT_DIR/docker-compose.spire.yml" up -d kms-service

printf '\n==> Positive mTLS E2E check\n'
docker compose -f "$ROOT_DIR/docker-compose.spire.yml" run --rm test-client sh -c '
  /usr/local/bin/spire-agent api fetch x509 -socketPath /tmp/spire-agent.sock -write /tmp/spire-test-client && \
  openssl s_client -connect kms-service:8080 -cert /tmp/spire-test-client/svid.pem -key /tmp/spire-test-client/key.pem -CAfile /tmp/spire-test-client/bundle.pem -verify_return_error -quiet </dev/null | head -c 256 || true
'

printf '\n==> Cleaning up\n'
docker compose -f "$ROOT_DIR/docker-compose.spire.yml" down -v --remove-orphans

printf '\nE2E lab script completed.\n'
