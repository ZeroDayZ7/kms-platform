-- Migration: 008_ceremonies.sql
-- Creates table for recording security ceremonies audit trail

CREATE TABLE IF NOT EXISTS ceremonies (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    kind TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'COMPLETED',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ceremonies_kind ON ceremonies(kind);
CREATE INDEX IF NOT EXISTS idx_ceremonies_created_at ON ceremonies(created_at DESC);