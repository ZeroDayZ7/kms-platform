-- name: InsertDbCredential :exec
INSERT INTO db_credentials (
    id,
    service_id,
    target_db,
    username,
    encrypted_password,
    nonce,
    kek_id,
    created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
);

-- name: GetDbCredentialByID :one
SELECT id, service_id, target_db, username, encrypted_password, nonce, kek_id, created_at
FROM db_credentials
WHERE id = $1
LIMIT 1;

-- name: GetLatestDbCredentialForService :one
SELECT id, service_id, target_db, username, encrypted_password, nonce, kek_id, created_at
FROM db_credentials
WHERE service_id = $1 AND target_db = $2
ORDER BY created_at DESC
LIMIT 1;

-- name: DeleteDbCredential :exec
DELETE FROM db_credentials
WHERE id = $1;