-- Migration: 006_client_identities.sql
-- Registry of authorized client identities (Admins, Agents, Services) for mTLS authentication & ACL.

CREATE TABLE IF NOT EXISTS client_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Identyfikatory X.509
    subject_cn TEXT NOT NULL UNIQUE,                  -- np. 'admin-root', 'agent-prod-worker-01'
    serial_number TEXT NOT NULL UNIQUE,              -- Numery seryjne certyfikatu (Hex/Dec String)
    fingerprint_sha256 TEXT NOT NULL UNIQUE,         -- Fingerprint certyfikatu (SHA-256)
    
    -- IAM / RBAC
    identity_type TEXT NOT NULL,                     -- 'ADMIN', 'AGENT', 'SERVICE'
    role TEXT NOT NULL DEFAULT 'OPERATOR',           -- 'SUPER_ADMIN', 'ADMIN', 'AGENT'
    
    -- Stan i Cykl Życia
    status TEXT NOT NULL DEFAULT 'ACTIVE',           -- 'ACTIVE', 'REVOKED', 'SUSPENDED'
    public_cert_pem TEXT NOT NULL,                   -- Certyfikat PEM w celach audytowych / weryfikacji
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,

    CONSTRAINT chk_identity_type CHECK (identity_type IN ('ADMIN', 'AGENT', 'SERVICE')),
    CONSTRAINT chk_identity_status CHECK (status IN ('ACTIVE', 'REVOKED', 'SUSPENDED'))
);

CREATE INDEX IF NOT EXISTS idx_client_identities_cn_status 
    ON client_identities (subject_cn, status);

CREATE INDEX IF NOT EXISTS idx_client_identities_fingerprint 
    ON client_identities (fingerprint_sha256);