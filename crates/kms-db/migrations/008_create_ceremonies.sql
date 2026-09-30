-- Migration: create ceremonies table
CREATE TABLE IF NOT EXISTS ceremonies (
    id UUID PRIMARY KEY,
    kind TEXT NOT NULL,
    payload BYTEA NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
