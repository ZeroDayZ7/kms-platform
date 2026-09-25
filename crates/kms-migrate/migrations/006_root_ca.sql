-- Migration: 006_root_ca.sql
-- Add table for storing Root CA metadata and encrypted private key

CREATE TABLE IF NOT EXISTS root_cas (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    ca_tag TEXT NOT NULL UNIQUE, -- logical identifier for the Root CA
    algorithm TEXT NOT NULL,
    encrypted_private_key BYTEA NOT NULL, -- [12 bytes Nonce] + [Ciphertext+AuthTag]
    kek_id UUID NOT NULL REFERENCES keys(id) ON DELETE RESTRICT,
    kek_version INT NOT NULL DEFAULT 1,
    certificate_pem TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_root_cas_tag ON root_cas(ca_tag);

CREATE INDEX IF NOT EXISTS idx_root_cas_expires ON root_cas (expires_at) WHERE expires_at IS NOT NULL;
