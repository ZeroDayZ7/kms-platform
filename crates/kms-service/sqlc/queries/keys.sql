-- name: GetActiveSigningPublicKeys :many
SELECT public_key_pem 
FROM keys 
WHERE purpose = 'Signing' AND is_active = TRUE;

-- name: GetActiveKey :one
SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at
FROM keys
WHERE service_id = $1 AND algorithm = $2 AND is_active = TRUE
ORDER BY version DESC
LIMIT 1;

-- name: GetKeyByVersion :one
SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at
FROM keys
WHERE service_id = $1 AND algorithm = $2 AND version = $3
LIMIT 1;

-- name: GetLatestActiveKeyForService :one
SELECT id
FROM keys
WHERE service_id = $1 AND is_active = TRUE
ORDER BY version DESC
LIMIT 1;

-- name: GetAllActiveKeys :many
SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at
FROM keys
WHERE is_active = TRUE;

-- name: SaveKey :exec
INSERT INTO keys (
    id,
    service_id,
    algorithm,
    version,
    encrypted_key_data,
    public_key_pem,
    purpose,
    status,
    is_active,
    created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()
)
ON CONFLICT (service_id, algorithm, version)
DO UPDATE SET
    encrypted_key_data = EXCLUDED.encrypted_key_data,
    public_key_pem = EXCLUDED.public_key_pem,
    purpose = EXCLUDED.purpose,
    status = EXCLUDED.status,
    is_active = EXCLUDED.is_active,
    created_at = NOW();

-- name: UpdateKeyStatus :exec
UPDATE keys
SET status = $2,
    is_active = $3,
    created_at = NOW()
WHERE id = $1;

-- name: UpdateEncryptedKey :exec
UPDATE keys
SET encrypted_key_data = $2
WHERE id = $1;

-- name: GetAllKeys :many
SELECT id, service_id, algorithm, version, encrypted_key_data, public_key_pem, purpose, status, is_active, created_at
FROM keys
ORDER BY created_at DESC;