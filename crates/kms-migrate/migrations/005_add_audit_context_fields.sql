-- Migration: 005_add_audit_context_fields.sql
-- Adds extended context fields (tracing & target metadata) to audit_logs.

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS request_id TEXT NULL,
    ADD COLUMN IF NOT EXISTS operation_id TEXT NULL,
    ADD COLUMN IF NOT EXISTS target_id TEXT NULL,
    ADD COLUMN IF NOT EXISTS metadata TEXT NULL;