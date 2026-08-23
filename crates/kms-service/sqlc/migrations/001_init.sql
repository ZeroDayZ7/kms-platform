CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS keys (
    id UUID PRIMARY KEY,
    service_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    version INT NOT NULL,
    encrypted_key_data BYTEA NOT NULL,
    public_key_pem TEXT NOT NULL DEFAULT '',
    purpose TEXT NOT NULL DEFAULT 'Signing',
    status TEXT NOT NULL DEFAULT 'Active',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (service_id, algorithm, version)
);

CREATE INDEX IF NOT EXISTS idx_keys_service_algorithm_active
    ON keys (service_id, algorithm, is_active);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_active_key_per_service_algorithm
    ON keys (service_id, algorithm)
    WHERE is_active = TRUE;

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY,
    caller_service TEXT NOT NULL,
    target_service TEXT NOT NULL,
    action TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NULL,
    prev_hash TEXT NULL,
    signature BYTEA NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at
    ON audit_logs (created_at DESC);
