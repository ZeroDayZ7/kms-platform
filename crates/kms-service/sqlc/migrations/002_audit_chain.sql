-- Migration: 002_audit_chain.sql
-- Add cryptographic hash chain fields and immutability trigger for audit_logs

-- Add `hash` column (hex SHA-256) and make `prev_hash` NOT NULL with genesis default
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS hash TEXT;

-- Ensure prev_hash exists and is NOT NULL (set existing NULLs to genesis)
UPDATE audit_logs
SET prev_hash = '0000000000000000000000000000000000000000000000000000000000000000'
WHERE prev_hash IS NULL;

ALTER TABLE audit_logs
    ALTER COLUMN prev_hash SET NOT NULL;

-- Make hash NOT NULL for future inserts (existing rows without hash will be backfilled by application logic)
ALTER TABLE audit_logs
    ALTER COLUMN hash SET NOT NULL;

-- Ensure signature column exists as BYTEA (nullable)
ALTER TABLE audit_logs
    ALTER COLUMN signature SET DATA TYPE bytea USING signature;

-- Create immutability function and trigger: disallow UPDATE or DELETE
CREATE OR REPLACE FUNCTION audit_logs_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Audit logs are append-only and cannot be modified or deleted';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON audit_logs;
CREATE TRIGGER trg_audit_logs_immutable
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();

-- Indexes to optimize retrieval of latest records and ordering
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at_desc ON audit_logs (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_hash ON audit_logs (hash);
