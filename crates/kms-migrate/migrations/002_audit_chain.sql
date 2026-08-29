-- Migration: 002_audit_chain.sql
-- Upgrades audit_logs to a cryptographic hash chain with append-only immutability.

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS hash TEXT NOT NULL DEFAULT '';

UPDATE audit_logs
SET prev_hash = '0000000000000000000000000000000000000000000000000000000000000000'
WHERE prev_hash IS NULL;

ALTER TABLE audit_logs
    ALTER COLUMN prev_hash SET NOT NULL,
    ALTER COLUMN prev_hash SET DEFAULT '0000000000000000000000000000000000000000000000000000000000000000';

ALTER TABLE audit_logs
    ALTER COLUMN signature SET DATA TYPE BYTEA USING signature;

-- Immutability trigger: disallow UPDATE or DELETE
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

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at_desc 
    ON audit_logs (created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_hash 
    ON audit_logs (hash);