use std::fs;
use std::path::Path;

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, UnixTime, pem::PemObject};
use webpki::{ALL_VERIFICATION_ALGS, EndEntityCert, KeyUsage};

use crate::domain::auth::{
    AuthError, Principal, TlsIdentity, WorkloadIdentityConfig, WorkloadIdentityProvider,
};

#[derive(Debug, Clone)]
pub struct SpiffeX509IdentityProvider {
    config: WorkloadIdentityConfig,
}

impl SpiffeX509IdentityProvider {
    pub fn new(config: WorkloadIdentityConfig) -> Self {
        Self { config }
    }

    pub fn extract_spiffe_uri_from_cert(&self, cert_bytes: &[u8]) -> Result<String, AuthError> {
        let cert_der = parse_leaf_certificate(cert_bytes)?;
        let end_entity = EndEntityCert::try_from(&cert_der)
            .map_err(|err| AuthError::UntrustedIdentity(format!("invalid X.509 certificate: {err}")))?;

        end_entity
            .valid_uri_names()
            .find(|uri| uri.starts_with("spiffe://"))
            .map(str::to_owned)
            .ok_or_else(|| {
                AuthError::UntrustedIdentity(
                    "SPIFFE certificate does not contain a valid spiffe:// URI SAN".to_string(),
                )
            })
    }

    pub fn validate_spiffe_identity(&self, cert_bytes: &[u8]) -> Result<Principal, AuthError> {
        if !self.config.enabled {
            return Err(AuthError::UntrustedIdentity(
                "SPIFFE workload identity verification is disabled".to_string(),
            ));
        }

        let uri = self.extract_spiffe_uri_from_cert(cert_bytes)?;

        if let Some(trust_domain) = &self.config.trust_domain {
            let expected_prefix = format!("spiffe://{trust_domain}");
            if !uri.starts_with(&expected_prefix) {
                return Err(AuthError::UntrustedIdentity(format!(
                    "SPIFFE trust domain mismatch: certificate URI '{uri}' does not match expected trust domain '{trust_domain}'"
                )));
            }
        }

        if let Some(expected_workload_id) = &self.config.workload_id {
            let expected = normalize_workload_id(expected_workload_id);
            let actual = normalize_workload_id(&uri);
            if actual != expected && !actual.starts_with(&format!("{expected}/")) {
                return Err(AuthError::UntrustedIdentity(format!(
                    "SPIFFE workload mismatch: expected '{expected_workload_id}' but certificate identified '{uri}'"
                )));
            }
        }

        Ok(Principal::spiffe(uri))
    }

    pub fn validate_certificate_chain(
        &self,
        cert_pem: &[u8],
        trust_bundle_pem: &[u8],
    ) -> Result<(), AuthError> {
        let leaf_cert = parse_leaf_certificate(cert_pem)?;
        let trust_anchors = load_trust_anchors(trust_bundle_pem)?;
        if trust_anchors.is_empty() {
            return Err(AuthError::UntrustedIdentity(
                "trust bundle is empty; mTLS verification must fail closed".to_string(),
            ));
        }

        let leaf = EndEntityCert::try_from(&leaf_cert)
            .map_err(|err| AuthError::UntrustedIdentity(format!("invalid leaf certificate: {err}")))?;

        leaf.verify_for_usage(
            ALL_VERIFICATION_ALGS,
            &trust_anchors,
            &[],
            UnixTime::now(),
            KeyUsage::client_auth(),
            None,
            None,
        )
        .map_err(|err| AuthError::UntrustedIdentity(format!("certificate chain validation failed: {err}")))?;

        Ok(())
    }

    pub fn load_pem_from_file(path: impl AsRef<Path>) -> Result<Vec<u8>, AuthError> {
        fs::read(path).map_err(|err| {
            AuthError::MissingMetadata(format!("failed to read certificate file: {err}"))
        })
    }
}

#[async_trait::async_trait]
impl WorkloadIdentityProvider for SpiffeX509IdentityProvider {
    async fn current_principal(&self) -> Result<Principal, AuthError> {
        let cert_path = self
            .config
            .tls_identity
            .certificate_path
            .clone()
            .ok_or_else(|| {
                AuthError::MissingMetadata("TLS certificate path is not configured".to_string())
            })?;
        let pem = Self::load_pem_from_file(cert_path)?;
        self.validate_spiffe_identity(&pem)
    }

    async fn tls_identity(&self) -> Result<TlsIdentity, AuthError> {
        Ok(self.config.tls_identity.clone())
    }
}

fn normalize_workload_id(value: &str) -> String {
    let trimmed = value.trim();
    let without_scheme = trimmed.strip_prefix("spiffe://").unwrap_or(trimmed);
    let normalized = without_scheme.trim_start_matches('/');
    if normalized.is_empty() {
        return "/".to_string();
    }
    format!("/{}", normalized.trim_end_matches('/'))
}

fn parse_leaf_certificate(cert_bytes: &[u8]) -> Result<CertificateDer<'static>, AuthError> {
    let cert = match CertificateDer::from_pem_slice(cert_bytes) {
        Ok(cert) => cert,
        Err(_) => CertificateDer::from(cert_bytes.to_vec()),
    };

    if cert.is_empty() {
        return Err(AuthError::UntrustedIdentity(
            "certificate payload is empty: mTLS verification must fail closed".to_string(),
        ));
    }

    Ok(cert)
}

fn load_trust_anchors(trust_bundle_pem: &[u8]) -> Result<Vec<rustls::pki_types::TrustAnchor<'static>>, AuthError> {
    let certs: Vec<_> = CertificateDer::pem_slice_iter(trust_bundle_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            AuthError::UntrustedIdentity(format!("invalid trust bundle PEM: {err}"))
        })?;

    if certs.is_empty() {
        return Err(AuthError::UntrustedIdentity(
            "trust bundle is empty; mTLS verification must fail closed".to_string(),
        ));
    }

    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(certs);
    Ok(roots.roots)
}

#[cfg(test)]
mod tests {
    use super::SpiffeX509IdentityProvider;
    use crate::domain::auth::WorkloadIdentityConfig;

    const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIDLzCCAhegAwIBAgIUUiuMFI9m5dhsxXx8r3RuFaioNV0wDQYJKoZIhvcNAQEL\nBQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5vcmcwHhcNMjYwOTE1MjExODQxWhcNMzYw\nOTEyMjExODQxWjAWMRQwEgYDVQQDDAtleGFtcGxlLm9yZzCCASIwDQYJKoZIhvcN\nAQEBBQADggEPADCCAQoCggEBAL6XOL6+NYCPA+KqHdLbGbJFYGk0eWIKSYhebEX2\nUKw4hJHiz9b+G5pYN8aSWP5eIvj7xvOEXkOieGyr50iIirFeboI4F1gAmc/9gO4l\nZ9TQLUhRosKvlTPn30c0QsgpWccCy4HehPP7Q2EhiuvHcn/b7ZEHK/tKYdMGv1BR\nnOUSItUfT9pdV4ujTOMTFyUClMa0LAY595OnJTAp0Ah6YYRAAFbWe06Kwl2jVlnh\n0X6AeQKu6jiby/7JQdItuWpu0nCfro6wK+I8Ey/1Jk65vrtlcm6dGFMYW1OpU5CO\naiDLjY5VVmxs8rOtcIjqS6o6QA/MWOMraPdFCZV0QmD8d2UCAwEAAaN1MHMwNwYD\nVR0RBDAwLoYsc3BpZmZlOi8vZXhhbXBsZS5vcmcvbnMvZGVmYXVsdC93b3JrbG9h\nZC9rbXMwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0OBBYEFO2Prxh1\nhR3nxfN+x6QN3BC/vH27MA0GCSqGSIb3DQEBCwUAA4IBAQC1BOq8yKDYip/Ldn7K\nrPEYGlbEZyQmJiqQhDunWXn3v5DIiFJlSIrk+bjQ2HdkYi7AuaPITwimYVsGwj3z\n4DSHcwDGJi1sFBvs5UiHoh9+41uOJAUTArjHjR0k0nA9IkqlyuZSJNzKYUMw4jwz\nSHG+GRs357Kl+EsNERYRJGSI/OormB1VZessPwSa93R888u3SyPv4xtXm6rDo0Kh\n1nb9yamHcHWSOwLrW27ILn6+Yup4/ap1ngiRSGdp8Hlwz3V3+9r6jiwTZDP3L0qF\nVEaWtcFxH3pILXXZAzaJFYUDo9RYNMzUsKP2e0vOTdkJRgRBJxfzP1YD3NkkcjjK\nCPGG\n-----END CERTIFICATE-----\n";

    #[test]
    fn parses_spiiffe_uri_san_from_pem() {
        let provider = SpiffeX509IdentityProvider::new(WorkloadIdentityConfig::default());
        let result = provider.extract_spiffe_uri_from_cert(CERT_PEM.as_bytes()).unwrap();
        assert_eq!(result, "spiffe://example.org/ns/default/workload/kms");
    }

    #[test]
    fn rejects_cert_when_trust_domain_does_not_match() {
        let provider = SpiffeX509IdentityProvider::new(WorkloadIdentityConfig {
            enabled: true,
            trust_domain: Some("other.org".to_string()),
            workload_id: Some("/ns/default/workload/kms".to_string()),
            ..Default::default()
        });

        let err = provider.validate_spiffe_identity(CERT_PEM.as_bytes()).unwrap_err();
        assert!(matches!(err, crate::domain::auth::AuthError::UntrustedIdentity(_)));
    }
}
