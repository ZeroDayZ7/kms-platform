#!/usr/bin/env bash
set -euo pipefail

# Wyłączenie automatycznej konwersji ścieżek w Git Bash (Windows)
export MSYS_NO_PATHCONV=1

# Wyznaczenie katalogu skryptu
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ==============================================================================
# Konfiguracja zmiennych
# ==============================================================================
SECRET="super-long-random-secret-for-kms-cli-hmac-64-bytes"
SERVICE_ID="kms_cli"
HOST="http://localhost:8080"
PATH_URI="/api/v1/admin/ceremony/lock"
METHOD="POST"

echo "🔒 Locking KMS: clearing master key from memory..."

# ==============================================================================
# Generowanie timestampu i podpisu HMAC-SHA256 przez Python
# ==============================================================================
TIMESTAMP=$(date +%s)
PY_EXE=$(command -v python3 || command -v python)

SIGNATURE=$("$PY_EXE" -c 'import sys, hmac, hashlib; secret, method, path, ts = sys.argv[1:5]; payload = f"{method}:{path}:{ts}".encode("utf-8"); print(hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest())' "$SECRET" "$METHOD" "$PATH_URI" "$TIMESTAMP")

# ==============================================================================
# Wykonanie zapytania HTTP
# ==============================================================================
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X $METHOD "${HOST}${PATH_URI}" \
  -H "Content-Type: application/json" \
  -H "X-Service-Name: $SERVICE_ID" \
  -H "X-Timestamp: $TIMESTAMP" \
  -H "X-HMAC-Signature: $SIGNATURE")

if [ "$RESPONSE" -eq 200 ]; then
    echo "✅ KMS successfully locked."
else
    echo "❌ Failed to lock KMS (HTTP Status: $RESPONSE)." >&2
    exit 1
fi