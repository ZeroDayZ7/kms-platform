#!/usr/bin/env bash
set -euo pipefail

KMS_URL="http://127.0.0.1:8080"
SERVICE_ID="auth-service"
# HMAC Secret z .env (ACL__SERVICES__AUTH_SERVICE__SECRET)
SECRET="super-long-random-secret-for-auth-service-hmac-64-bytes"

echo "=== [DEV AGENT] 1. Testowanie Provisioningu Poświadczeń (Postgres) ==="
TIMESTAMP=$(date -u +%s)
PAYLOAD='{"service_id":"auth-service","target_type":"postgres","target_db":"orders_db","resource":"orders_db/tables/*"}'

# Generowanie prostego nagłówka auth dla dev agenta (lub bearer token / hmac zależnie od middleware extractor)
RESPONSE=$(curl -s -X POST "${KMS_URL}/api/v1/credentials/provision" \
  -H "Content-Type: application/json" \
  -H "X-Service-Id: ${SERVICE_ID}" \
  -H "X-Signature: ${SECRET}" \
  -d "${PAYLOAD}")

echo "Odpowiedź KMS:"
echo "${RESPONSE}" | jq .

echo "=== [DEV AGENT] 2. Testowanie Odmowy IAM (Forbidden Resource) ==="
PAYLOAD_FORBIDDEN='{"service_id":"auth-service","target_type":"unauthorized_target","target_db":"secret_db","resource":"forbidden/*"}'

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${KMS_URL}/api/v1/credentials/provision" \
  -H "Content-Type: application/json" \
  -H "X-Service-Id: ${SERVICE_ID}" \
  -H "X-Signature: ${SECRET}" \
  -d "${PAYLOAD_FORBIDDEN}")

echo "Status odpowiedzi (Oczekiwane 403): ${HTTP_STATUS}"
if [ "$HTTP_STATUS" -eq 403 ]; then
  echo "✔ Test IAM Denial zaliczony pomyślnie."
else
  echo "✖ Test IAM Denial NIEZALICZONY!"
  exit 1
fi