#!/usr/bin/env bash
set -euo pipefail

# Wyłączenie automatycznej konwersji ścieżek w Git Bash (Windows)
export MSYS_NO_PATHCONV=1

# Wyznaczenie katalogu, w którym znajduje się ten skrypt
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ==============================================================================
# Konfiguracja zmiennych na sztywno
# ==============================================================================
SECRET="super-long-random-secret-for-kms-cli-hmac-64-bytes"
SERVICE_ID="kms_cli"
HOST="http://localhost:8080"
PATH_URI="/api/v1/admin/ceremony/unlock"
METHOD="POST"
SHARES_DIR="$SCRIPT_DIR/shares"

# ==============================================================================
# Wczytanie kluczy (shares) z katalogu
# ==============================================================================
if [ ! -d "$SHARES_DIR" ]; then
    echo "❌ Błąd: Katalog '$SHARES_DIR' nie istnieje!" >&2
    exit 1
fi

SHARE_FILES=$(find "$SHARES_DIR" -maxdepth 1 -name "*.json" | sort)
COUNT=$(echo "$SHARE_FILES" | grep -c '^' || true)

if [ "$COUNT" -eq 0 ]; then
    echo "❌ Błąd: Brak plików .json w '$SHARES_DIR'!" >&2
    exit 1
fi

SHARES_ARRAY=""
for file in $SHARE_FILES; do
    VAL=$(grep -oE '"[^"]+:[^"]+"' "$file" | head -n 1 | tr -d '"' || true)
    if [ -z "$VAL" ]; then
        VAL=$(grep -oE '"[^"]+"' "$file" | head -n 1 | tr -d '"' || true)
    fi
    if [ -n "$SHARES_ARRAY" ]; then
        SHARES_ARRAY="${SHARES_ARRAY},\"${VAL}\""
    else
        SHARES_ARRAY="\"${VAL}\""
    fi
done

BODY="{\"shares\":[${SHARES_ARRAY}]}"

echo "=== KMS Unlock CLI ==="
echo "Wczytane pliki z 'scripts/shares/': $COUNT"
echo "Identyfikator usługi: $SERVICE_ID"

# ==============================================================================
# Generowanie timestampu i podpisu HMAC-SHA256 przez Python
# ==============================================================================
TIMESTAMP=$(date +%s)

PY_EXE=$(command -v python3 || command -v python)
SIGNATURE=$("$PY_EXE" -c 'import sys, hmac, hashlib; secret, method, path, ts = sys.argv[1:5]; payload = f"{method}:{path}:{ts}".encode("utf-8"); print(hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest())' "$SECRET" "$METHOD" "$PATH_URI" "$TIMESTAMP")

CURL_CMD="curl -i -X $METHOD \"${HOST}${PATH_URI}\" \
  -H \"Content-Type: application/json\" \
  -H \"X-Service-Name: $SERVICE_ID\" \
  -H \"X-Timestamp: $TIMESTAMP\" \
  -H \"X-HMAC-Signature: $SIGNATURE\" \
  -d '$BODY'"

echo "Wygenerowany podpis: $SIGNATURE"
echo ""
echo "1) Wykonaj odblokowanie natychmiast"
echo "2) Wygeneruj komendę curl do skopiowania"
read -rp "Wybierz opcję [1/2]: " OPTION

case "$OPTION" in
    1)
        echo -e "\n=== Wysyłanie żądania do serwera... ==="
        eval "$CURL_CMD"
        echo ""
        ;;
    2)
        echo -e "\n=== Gotowa komenda curl dla Git Bash ==="
        echo "MSYS_NO_PATHCONV=1 curl -X $METHOD \"${HOST}${PATH_URI}\" \\"
        echo "  -H \"Content-Type: application/json\" \\"
        echo "  -H \"X-Service-Name: $SERVICE_ID\" \\"
        echo "  -H \"X-Timestamp: $TIMESTAMP\" \\"
        echo "  -H \"X-HMAC-Signature: $SIGNATURE\" \\"
        echo "  -d '$BODY'"
        echo ""
        ;;
    *)
        echo "❌ Niepoprawny wybór. Anulowano."
        exit 1
        ;;
esac