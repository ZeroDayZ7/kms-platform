-- Target systems (admin connections managed by KMS)
CREATE TABLE target_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_name VARCHAR(64) UNIQUE NOT NULL, -- np. 'postgres_auth', 'postgres_citizen', 'rabbit_prod', 'minio_s3'
    target_type VARCHAR(32) NOT NULL, -- 'postgresql', 'rabbitmq', 'minio'
    connection_url_encrypted BYTEA NOT NULL, -- zaszyfrowane connection string / master credentials
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Active provisioned dynamic credentials
CREATE TABLE provisioned_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id VARCHAR(64) NOT NULL,
    target_id UUID NOT NULL REFERENCES target_resources(id),
    username VARCHAR(128) NOT NULL,
    password_encrypted BYTEA NOT NULL,
    granted_role VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_provisioned_credentials_service ON provisioned_credentials(service_id);
CREATE INDEX idx_provisioned_credentials_expires ON provisioned_credentials(expires_at) WHERE revoked = false;