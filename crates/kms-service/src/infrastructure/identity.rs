use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, UnixTime, pem::PemObject};
use webpki::{ALL_VERIFICATION_ALGS, EndEntityCert, KeyUsage};

#[cfg(unix)]
use tokio::net::UnixStream;

use crate::domain::auth::{
    AuthError, Principal, TlsIdentity, WorkloadIdentityConfig, WorkloadIdentityProvider,
};

#[derive(Debug, Clone)]
pub struct SpireWorkloadApiClient {
    socket_path: String,
}

impl SpireWorkloadApiClient {
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub async fn fetch_workload_svid(&self) -> Result<Vec<u8>, AuthError> {
        let body = self
            .fetch_http_json("/spire-agent/api/agent/v1/workload/svid")
            .await?;
        let response: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|err| AuthError::Failed(format!("invalid SPIRE Workload API SVID response: {err}")))?;

        let mut x509 = None;
        if let Some(svids) = response.get("svids").and_then(|v| v.as_array()) {
            x509 = svids
                .iter()
                .filter_map(|entry| {
                    let maybe = entry.get("x509_svids")
                        .and_then(|v| v.as_array())
                        .and_then(|items| items.first())
                        .and_then(|v| v.as_object());
                    maybe.or_else(|| entry.get("x509_svid").and_then(|v| v.as_object()))
                })
                .find_map(|entry| {
                    let empty = Vec::new();
                    let certs = entry
                        .get("cert_chain")
                        .and_then(|v| v.as_array())
                        .or_else(|| entry.get("certs").and_then(|v| v.as_array()))
                        .unwrap_or(&empty);
                    let cert_pem = certs
                        .iter()
                        .filter_map(|value| value.as_str())
                        .collect::<Vec<_>>()
                        .join("\n");
                    if !cert_pem.trim().is_empty() {
                        Some(format!("{cert_pem}\n").into_bytes())
                    } else {
                        None
                    }
                });
        }

        if x509.is_none() {
            if let Some(entry) = response.get("svid")
                .and_then(|v| v.as_object())
                .and_then(|v| v.get("certs"))
                .and_then(|v| v.as_array())
            {
                let cert_pem = entry
                    .iter()
                    .filter_map(|value| value.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                if !cert_pem.trim().is_empty() {
                    x509 = Some(format!("{cert_pem}\n").into_bytes());
                }
            }
        }

        let x509 = x509.ok_or_else(|| {
            AuthError::UntrustedIdentity(
                "SPIRE Workload API returned no X.509 SVID certificate chain for the workload".to_string(),
            )
        })?;

        Ok(x509)
    }

    pub async fn fetch_trust_bundle(&self) -> Result<Vec<u8>, AuthError> {
        let body = self
            .fetch_http_json("/spire-agent/api/agent/v1/bundle")
            .await?;

        let response: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|err| AuthError::Failed(format!("invalid SPIRE trust bundle response: {err}")))?;

        let mut pem = Vec::new();
        if let Some(bundles) = response.get("bundles").and_then(|v| v.as_object()) {
            for value in bundles.values() {
                if let Some(root_certs) = value.get("root_certs").and_then(|v| v.as_array()) {
                    for cert in root_certs {
                        if let Some(c) = cert.get("cert") .and_then(|v| v.as_str()) {
                            pem.extend_from_slice(c.as_bytes());
                            pem.push(b'\n');
                        }
                    }
                }
            }
        }
        if let Some(root_certs) = response.get("root_certs").and_then(|v| v.as_array()) {
            for cert in root_certs {
                if let Some(c) = cert.get("cert").and_then(|v| v.as_str()) {
                    pem.extend_from_slice(c.as_bytes());
                    pem.push(b'\n');
                }
            }
        }

        if pem.is_empty() {
            return Err(AuthError::UntrustedIdentity(
                "SPIRE Workload API returned an empty trust bundle; fail closed".to_string(),
            ));
        }

        Ok(pem)
    }

    async fn fetch_http_json(&self, _path: &str) -> Result<Vec<u8>, AuthError> {
        #[cfg(unix)]
        {
            let mut stream = UnixStream::connect(&self.socket_path)
                .await
                .map_err(|err| {
                    AuthError::MissingMetadata(format!(
                        "failed to connect to SPIRE agent socket '{}': {err}",
                        self.socket_path
                    ))
                })?;

            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: spire-agent\r\nConnection: close\r\n\r\n"
            );

            stream
                .write_all(request.as_bytes())
                .await
                .map_err(|err| AuthError::Failed(format!("failed to send SPIRE Workload API request: {err}")))?;

            let mut response = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let read = stream
                    .read(&mut buffer)
                    .await
                    .map_err(|err| AuthError::Failed(format!("failed to read SPIRE Workload API response: {err}")))?;
                if read == 0 {
                    break;
                }
                response.extend_from_slice(&buffer[..read]);
                if response.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }

            let payload = String::from_utf8_lossy(&response);
            let Some((_, body)) = payload.split_once("\r\n\r\n") else {
                return Err(AuthError::Failed(
                    "SPIRE Workload API response was incomplete or malformed".to_string(),
                ));
            };

            let content_length = payload
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(body.len());

            let body_bytes = body.as_bytes();
            if body_bytes.len() < content_length {
                let mut rest = Vec::new();
                loop {
                    let read = stream
                        .read(&mut buffer)
                        .await
                        .map_err(|err| AuthError::Failed(format!("failed to finish reading SPIRE Workload API body: {err}")))?;
                    if read == 0 {
                        break;
                    }
                    rest.extend_from_slice(&buffer[..read]);
                    if rest.len() >= content_length - body_bytes.len() {
                        break;
                    }
                }
                let mut combined = body.as_bytes().to_vec();
                combined.extend_from_slice(&rest);
                return Ok(combined);
            }

            return Ok(body.as_bytes()[..content_length.min(body.len())].to_vec());
        }

        #[cfg(not(unix))]
        Err(AuthError::MissingMetadata(
            "SPIRE Workload API over Unix domain sockets is not supported on this platform".to_string(),
        ))
    }
}

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

    pub async fn current_runtime_identity(&self) -> Result<Principal, AuthError> {
        let socket_path = self
            .config
            .spire_agent_socket_path
            .clone()
            .ok_or_else(|| {
                AuthError::MissingMetadata(
                    "SPIRE agent socket path is not configured for workload identity".to_string(),
                )
            })?;

        let client = SpireWorkloadApiClient::new(socket_path);
        let certs = client.fetch_workload_svid().await?;
        self.validate_spiffe_identity(&certs)
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

    async fn fetch_identity(&self) -> Result<crate::domain::auth::TlsIdentitySnapshot, AuthError> {
        // Determine certificate chain PEM: prefer configured file, otherwise the SPIRE Workload API
        let cert_pem: Vec<u8> = match &self.config.tls_identity.certificate_path {
            Some(path) => Self::load_pem_from_file(path.clone())?,
            None => {
                let socket_path = self
                    .config
                    .spire_agent_socket_path
                    .clone()
                    .ok_or_else(|| {
                        AuthError::MissingMetadata(
                            "SPIRE agent socket path is not configured and no certificate_path provided".to_string(),
                        )
                    })?;
                let client = SpireWorkloadApiClient::new(socket_path);
                client.fetch_workload_svid().await?
            }
        };

        // Determine trust bundle PEM
        let trust_pem: Vec<u8> = match &self.config.tls_identity.trust_bundle_path {
            Some(path) => Self::load_pem_from_file(path.clone())?,
            None => {
                let socket_path = self
                    .config
                    .spire_agent_socket_path
                    .clone()
                    .ok_or_else(|| {
                        AuthError::MissingMetadata(
                            "SPIRE agent socket path is not configured and no trust_bundle_path provided".to_string(),
                        )
                    })?;
                let client = SpireWorkloadApiClient::new(socket_path);
                client.fetch_trust_bundle().await?
            }
        };

        // Load private key bytes from configured path
        let key_bytes: Vec<u8> = match &self.config.tls_identity.key_path {
            Some(path) => Self::load_pem_from_file(path.clone())?,
            None => {
                return Err(AuthError::MissingMetadata(
                    "TLS private key path is not configured; cannot build runtime identity".to_string(),
                ));
            }
        };

        // Validate certificate chain against trust bundle
        self.validate_certificate_chain(&cert_pem, &trust_pem)?;

        // Extract SPIFFE ID
        let spiffe = self.extract_spiffe_uri_from_cert(&cert_pem)?;

        // Build snapshot with conservative validity window (best-effort)
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        let not_before = now - 60;
        let not_after = now + 86400; // 24h as a default window

        let generation = now as u64;

        Ok(crate::domain::auth::TlsIdentitySnapshot {
            certificate_chain_pem: cert_pem,
            private_key: crate::domain::crypto::SecretBytes::new(key_bytes),
            trust_bundle_pem: trust_pem,
            spiffe_id: spiffe,
            not_before,
            not_after,
            generation,
        })
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
