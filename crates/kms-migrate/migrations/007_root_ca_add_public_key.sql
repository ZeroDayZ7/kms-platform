-- Migration: 007_root_ca_add_public_key.sql
-- Add public_key column to root_cas to store public key bytes (SEC1 uncompressed)

ALTER TABLE root_cas
    ADD COLUMN IF NOT EXISTS public_key BYTEA DEFAULT NULL;

-- Optional: create index if needed later
