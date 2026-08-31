-- 007_pki_state.sql
-- Persist encrypted Root CA blobs for on-demand PKI

CREATE TABLE IF NOT EXISTS pki_root_state (
    id INT PRIMARY KEY DEFAULT 1,
    ca_subject_cn TEXT NOT NULL,
    ca_certificate_pem TEXT NOT NULL,
    encrypted_ca_key BYTEA NOT NULL,
    system_ca_kek_wrapped BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT single_root_ca CHECK (id = 1)
);
