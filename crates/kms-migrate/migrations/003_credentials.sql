-- Migration: 003_credentials.sql
-- Production-ready credential storage with lifecycle support and resource tracking.

CREATE TABLE IF NOT EXISTS db_credentials (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    service_id TEXT NOT NULL,
    target_type TEXT NOT NULL,         -- 'postgres', 'minio', 'rabbitmq'
    target_db TEXT NOT NULL,           -- database name / bucket name / vhost
    resource TEXT NOT NULL DEFAULT '',  -- host/cluster ARN or specific resource
    encrypted_credentials BYTEA NOT NULL, -- [12 bytes Nonce] + [Ciphertext+AuthTag] of JSON {u,p}
    kek_id UUID NOT NULL REFERENCES keys(id) ON DELETE RESTRICT,
    kek_version INT NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'ACTIVE', -- 'ACTIVE', 'REVOKED', 'EXPIRED'
    expires_at TIMESTAMPTZ NULL,       -- NULL = permanent, TIMESTAMP = ephemeral credential
    revoked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_credentials_status CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED'))
);

CREATE INDEX IF NOT EXISTS idx_db_credentials_service_lookup
    ON db_credentials (service_id, target_type, target_db, status);

CREATE INDEX IF NOT EXISTS idx_db_credentials_expiration
    ON db_credentials (expires_at)
    WHERE status = 'ACTIVE' AND expires_at IS NOT NULL;