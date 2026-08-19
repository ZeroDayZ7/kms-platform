#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Dedicated lock script - calls the local CLI kms-service lock command
# Does not require HTTP authorization (OS process-level permissions)
# ==============================================================================

# Wyznaczenie katalogu, w którym znajduje się ten skrypt
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ścieżka do binarki KMS (w kontenerze lub lokalnie)
KMS_BIN="${KMS_BIN:-kms-service}"

echo "🔒 Locking KMS: clearing master key from memory..."
if "$KMS_BIN" lock; then
    echo "✅ KMS successfully locked."
else
    echo "❌ Failed to lock KMS." >&2
    exit 1
fi
