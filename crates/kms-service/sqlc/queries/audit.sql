-- name: GetLastAuditLog :one
SELECT id, caller_service, target_service, action, algorithm, status, reason, prev_hash, hash, signature, created_at
FROM audit_logs
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: GetAuditLogsLastN :many
SELECT id, caller_service, target_service, action, algorithm, status, reason, prev_hash, hash, signature, created_at
FROM audit_logs
ORDER BY created_at DESC, id DESC
LIMIT $1;

-- name: GetAuditLogsAll :many
SELECT id, caller_service, target_service, action, algorithm, status, reason, prev_hash, hash, signature, created_at
FROM audit_logs
ORDER BY created_at ASC, id ASC;

-- name: InsertAuditLog :exec
INSERT INTO audit_logs (
    id,
    caller_service,
    target_service,
    action,
    algorithm,
    status,
    reason,
    prev_hash,
    hash,
    signature,
    created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW()
);
