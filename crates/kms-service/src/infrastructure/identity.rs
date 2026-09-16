use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use base64::{Engine as _, engine::general_purpose::STANDARD};
use pkcs8::{PrivateKeyInfo, SubjectPublicKeyInfoRef};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, UnixTime, pem::PemObject};
use subtle::ConstantTimeEq;
use webpki::{ALL_VERIFICATION_ALGS, EndEntityCert, KeyUsage};

#[cfg(unix)]
use http::StatusCode;
#[cfg(unix)]
use http_body_util::Full;
#[cfg(unix)]
use hyper::Request;
#[cfg(unix)]
use hyper::body::Bytes;
#[cfg(unix)]
use hyper::client::conn::http2;
#[cfg(unix)]
use hyper_util::rt::TokioIo;
#[cfg(unix)]
use tokio::net::UnixStream;

use crate::domain::auth::{
    AuthError, Principal, TlsIdentity, WorkloadIdentityConfig, WorkloadIdentityProvider,
};

#[cfg(unix)]
#[derive(Debug, Clone, Default)]
struct X509SVID {
    spiffe_id: String,
    x509_svid: Vec<u8>,
    x509_svid_key: Vec<u8>,
    bundle: Vec<u8>,
    hint: String,
}

#[cfg(unix)]
#[derive(Debug, Clone, Default)]
struct X509SVIDResponse {
    svids: Vec<X509SVID>,
}

#[cfg(unix)]
fn decode_varint(bytes: &[u8], offset: &mut usize) -> Result<u64, AuthError> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        if *offset >= bytes.len() {
            return Err(AuthError::Failed(
                "truncated protobuf varint while decoding SPIRE Workload API response".to_string(),
            ));
        }
        let byte = bytes[*offset];
        *offset += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 64 {
            return Err(AuthError::Failed(
                "overlong protobuf varint while decoding SPIRE Workload API response".to_string(),
            ));
        }
    }
}

#[cfg(unix)]
fn decode_length_delimited(data: &[u8], offset: &mut usize) -> Result<Vec<u8>, AuthError> {
    let length = decode_varint(data, offset)? as usize;
    if *offset + length > data.len() {
        return Err(AuthError::Failed(
            "protobuf length-delimited field exceeds the SPIRE Workload API response size"
                .to_string(),
        ));
    }
    let value = data[*offset..*offset + length].to_vec();
    *offset += length;
    Ok(value)
}

#[cfg(unix)]
fn decode_string(data: &[u8], offset: &mut usize) -> Result<String, AuthError> {
    let bytes = decode_length_delimited(data, offset)?;
    String::from_utf8(bytes).map_err(|err| {
        AuthError::Failed(format!(
            "invalid UTF-8 SPIRE Workload API string field: {err}"
        ))
    })
}

#[cfg(unix)]
fn decode_x509_svid_response(data: &[u8]) -> Result<X509SVIDResponse, AuthError> {
    let mut offset = 0usize;
    let mut response = X509SVIDResponse::default();
    while offset < data.len() {
        let field = decode_varint(data, &mut offset)?;
        let wire_type = field & 0x07;
        let field_number = (field >> 3) as u32;
        match wire_type {
            0 => {
                let _ = decode_varint(data, &mut offset)?;
            }
            1 => {
                let _ = decode_length_delimited(data, &mut offset)?;
            }
            2 => {
                let value = decode_length_delimited(data, &mut offset)?;
                if field_number == 1 {
                    let mut inner = 0usize;
                    let mut svid = X509SVID::default();
                    while inner < value.len() {
                        let tag = decode_varint(&value, &mut inner)?;
                        let type_id = tag & 0x07;
                        let number = (tag >> 3) as u32;
                        match type_id {
                            0 => {
                                let _ = decode_varint(&value, &mut inner)?;
                            }
                            2 => {
                                let bytes = decode_length_delimited(&value, &mut inner)?;
                                match number {
                                    1 => {
                                        svid.spiffe_id =
                                            String::from_utf8(bytes).unwrap_or_default()
                                    }
                                    2 => svid.x509_svid = bytes,
                                    3 => svid.x509_svid_key = bytes,
                                    4 => svid.bundle = bytes,
                                    5 => svid.hint = String::from_utf8(bytes).unwrap_or_default(),
                                    _ => {}
                                }
                            }
                            _ => {
                                return Err(AuthError::Failed(format!(
                                    "unsupported SPIRE Workload API wire type {type_id} for field {number}"
                                )));
                            }
                        }
                    }
                    response.svids.push(svid);
                }
            }
            5 => {
                let _ = decode_length_delimited(data, &mut offset)?;
            }
            _ => {
                return Err(AuthError::Failed(format!(
                    "unsupported SPIRE Workload API protobuf wire type {wire_type} while decoding field {field_number}"
                )));
            }
        }
    }
    Ok(response)
}

#[cfg(unix)]
fn grpc_encode_message(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 5);
    frame.push(0u8);
    frame.extend_from_slice(&((payload.len() as u32).to_be_bytes()));
    frame.extend_from_slice(payload);
    frame
}

#[cfg(unix)]
fn parse_grpc_frames(data: &[u8]) -> Result<Vec<Vec<u8>>, AuthError> {
    let mut frames = Vec::new();
    let mut offset = 0;

    while offset + 5 <= data.len() {
        let compressed = data[offset];
        if compressed != 0 {
            return Err(AuthError::Failed(
                "compressed gRPC messages are not supported by this SPIRE Workload API client"
                    .to_string(),
            ));
        }

        let length = u32::from_be_bytes([
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
        ]) as usize;
        offset += 5;
        if offset + length > data.len() {
            return Err(AuthError::Failed(
                "truncated gRPC Workload API response payload received from SPIRE".to_string(),
            ));
        }

        frames.push(data[offset..offset + length].to_vec());
        offset += length;
    }

    Ok(frames)
}

#[cfg(unix)]
fn der_to_pem(der: &[u8], label: &str) -> Vec<u8> {
    let encoded = STANDARD.encode(der);
    let mut pem = Vec::new();
    pem.extend_from_slice(format!("-----BEGIN {label}-----\n").as_bytes());
    for chunk in encoded.as_bytes().chunks(64) {
        pem.extend_from_slice(chunk);
        pem.push(b'\n');
    }
    pem.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
    pem
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct SpireWorkloadApiClient {
    socket_path: String,
}

#[cfg(unix)]
impl SpireWorkloadApiClient {
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub async fn fetch_workload_svid(&self) -> Result<Vec<u8>, AuthError> {
        let response = self.fetch_x509_svid_response().await?;
        let svid = response
            .svids
            .into_iter()
            .find(|s| !s.spiffe_id.is_empty())
            .ok_or_else(|| {
                AuthError::UntrustedIdentity(
                    "SPIRE Workload API returned no X.509 SVID records for the workload"
                        .to_string(),
                )
            })?;

        Ok(der_to_pem(&svid.x509_svid, "CERTIFICATE"))
    }

    pub async fn fetch_trust_bundle(&self) -> Result<Vec<u8>, AuthError> {
        let response = self.fetch_x509_svid_response().await?;
        let svid = response
            .svids
            .into_iter()
            .find(|s| !s.spiffe_id.is_empty())
            .ok_or_else(|| {
                AuthError::UntrustedIdentity(
                    "SPIRE Workload API returned no trust bundle for the workload".to_string(),
                )
            })?;

        let bundle = if svid.bundle.is_empty() {
            return Err(AuthError::UntrustedIdentity(
                "SPIRE Workload API returned an empty trust bundle; fail closed".to_string(),
            ));
        } else {
            svid.bundle
        };

        Ok(der_to_pem(&bundle, "CERTIFICATE"))
    }

    async fn fetch_x509_svid_response(&self) -> Result<X509SVIDResponse, AuthError> {
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

            let (sender, connection) =
                http2::handshake(TokioIo::new(&mut stream))
                    .await
                    .map_err(|err| {
                        AuthError::Failed(format!(
                            "failed to establish HTTP/2 connection to SPIRE Workload API: {err}"
                        ))
                    })?;

            tokio::spawn(async move {
                if let Err(err) = connection.await {
                    tracing::warn!(error = %err, "SPIRE Workload API connection closed");
                }
            });

            let request_body = Vec::new();
            let grpc_body = grpc_encode_message(&request_body);
            let request = Request::builder()
                .method(http::Method::POST)
                .uri("http://localhost/SpiffeWorkloadAPI/FetchX509SVID")
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .body(Full::new(Bytes::from(grpc_body)))
                .map_err(|err| {
                    AuthError::Failed(format!("failed to build gRPC Workload API request: {err}"))
                })?;

            let response = sender.send_request(request).await.map_err(|err| {
                AuthError::Failed(format!(
                    "failed to send SPIRE gRPC FetchX509SVID request: {err}"
                ))
            })?;

            if response.status() != StatusCode::OK {
                return Err(AuthError::Failed(format!(
                    "SPIRE Workload API rejected FetchX509SVID with HTTP status {}",
                    response.status()
                )));
            }

            let status = response
                .headers()
                .get("grpc-status")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("0");
            if status != "0" {
                let message = response
                    .headers()
                    .get("grpc-message")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("unknown gRPC SPIRE error");
                return Err(AuthError::Failed(format!(
                    "SPIRE Workload API returned gRPC status '{status}': {message}"
                )));
            }

            let mut chunks = Vec::new();
            let mut body = response.into_body();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.map_err(|err| {
                    AuthError::Failed(format!(
                        "failed to read SPIRE Workload API response body: {err}"
                    ))
                })?;
                if chunk.is_empty() {
                    continue;
                }
                chunks.extend_from_slice(&chunk);
                if let Ok(frames) = parse_grpc_frames(&chunks) {
                    if let Some(message) = frames.into_iter().find(|frame| !frame.is_empty()) {
                        return decode_x509_svid_response(&message).map_err(|err| {
                            AuthError::Failed(format!(
                                "invalid SPIRE Workload API X509SVID response: {err}"
                            ))
                        });
                    }
                }
            }

            let frames = parse_grpc_frames(&chunks)?;
            let message = frames
                .into_iter()
                .find(|frame| !frame.is_empty())
                .ok_or_else(|| {
                    AuthError::UntrustedIdentity(
                        "SPIRE Workload API returned an empty X.509 SVID stream".to_string(),
                    )
                })?;

            decode_x509_svid_response(&message).map_err(|err| {
                AuthError::Failed(format!(
                    "invalid SPIRE Workload API X509SVID response: {err}"
                ))
            })
        }

        #[cfg(not(unix))]
        {
            Err(AuthError::MissingMetadata(
                "SPIRE Workload API over Unix domain sockets is not supported on this platform"
                    .to_string(),
            ))
        }
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
        let end_entity = EndEntityCert::try_from(&cert_der).map_err(|err| {
            AuthError::UntrustedIdentity(format!("invalid X.509 certificate: {err}"))
        })?;

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
        let expected = self.expected_spiffe_uri()?;

        if uri != expected {
            return Err(AuthError::UntrustedIdentity(format!(
                "SPIFFE identity mismatch: expected '{expected}' but certificate identified '{uri}'"
            )));
        }

        Ok(Principal::spiffe(uri))
    }

    fn expected_spiffe_uri(&self) -> Result<String, AuthError> {
        let trust_domain = self.config.trust_domain.as_deref().ok_or_else(|| {
            AuthError::MissingMetadata("SPIFFE trust domain is not configured".to_string())
        })?;
        let workload_id = self.config.workload_id.as_deref().ok_or_else(|| {
            AuthError::MissingMetadata("SPIFFE workload ID is not configured".to_string())
        })?;

        let normalized_workload = normalize_workload_id(workload_id);
        if normalized_workload == "/" {
            return Ok(format!("spiffe://{trust_domain}"));
        }
        Ok(format!("spiffe://{trust_domain}{normalized_workload}"))
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

        let leaf = EndEntityCert::try_from(&leaf_cert).map_err(|err| {
            AuthError::UntrustedIdentity(format!("invalid leaf certificate: {err}"))
        })?;

        leaf.verify_for_usage(
            ALL_VERIFICATION_ALGS,
            &trust_anchors,
            &[],
            UnixTime::now(),
            KeyUsage::client_auth(),
            None,
            None,
        )
        .map_err(|err| {
            AuthError::UntrustedIdentity(format!("certificate chain validation failed: {err}"))
        })?;

        Ok(())
    }

    pub fn validate_private_key_matches_cert(
        &self,
        cert_pem: &[u8],
        key_bytes: &[u8],
    ) -> Result<(), AuthError> {
        let cert_der = parse_leaf_certificate(cert_pem)?;
        let cert_public = EndEntityCert::try_from(&cert_der)
            .map_err(|err| {
                AuthError::UntrustedIdentity(format!(
                    "invalid certificate for private-key validation: {err}"
                ))
            })?
            .subject_public_key_info();
        let cert_public =
            SubjectPublicKeyInfoRef::try_from(cert_public.as_ref()).map_err(|err| {
                AuthError::UntrustedIdentity(format!(
                    "failed to decode certificate public key info: {err}"
                ))
            })?;
        let cert_public_bytes = cert_public.subject_public_key.as_bytes().ok_or_else(|| {
            AuthError::UntrustedIdentity(
                "certificate public key is malformed; reject identity snapshot".to_string(),
            )
        })?;

        let private_public = Self::pkcs8_public_key_from_private_key(key_bytes)?;

        if cert_public_bytes.ct_eq(&private_public).into() {
            Ok(())
        } else {
            Err(AuthError::UntrustedIdentity(
                "certificate and private key do not match; reject identity snapshot".to_string(),
            ))
        }
    }

    fn pkcs8_public_key_from_private_key(key_bytes: &[u8]) -> Result<Vec<u8>, AuthError> {
        match PrivateKeyInfo::try_from(key_bytes) {
            Ok(key_info) => key_info
                .public_key
                .map(|bytes| bytes.to_vec())
                .ok_or_else(|| {
                    AuthError::UntrustedIdentity(
                        "private key is missing its embedded public key; reject identity snapshot"
                            .to_string(),
                    )
                }),
            Err(_) => {
                let pem = std::str::from_utf8(key_bytes).map_err(|err| {
                    AuthError::UntrustedIdentity(format!("invalid private key payload: {err}"))
                })?;
                let (_, document) = pkcs8::der::Document::from_pem(pem).map_err(|err| {
                    AuthError::UntrustedIdentity(format!(
                        "invalid private key for certificate validation: {err}"
                    ))
                })?;
                let key_info = PrivateKeyInfo::try_from(document.as_bytes()).map_err(|err| {
                    AuthError::UntrustedIdentity(format!(
                        "invalid PKCS#8 private key for certificate validation: {err}"
                    ))
                })?;
                key_info
                    .public_key
                    .map(|bytes| bytes.to_vec())
                    .ok_or_else(|| {
                        AuthError::UntrustedIdentity(
                        "private key is missing its embedded public key; reject identity snapshot"
                            .to_string(),
                    )
                    })
            }
        }
    }

    pub fn load_pem_from_file(path: impl AsRef<Path>) -> Result<Vec<u8>, AuthError> {
        fs::read(path).map_err(|err| {
            AuthError::MissingMetadata(format!("failed to read certificate file: {err}"))
        })
    }

    #[cfg(unix)]
    pub async fn current_runtime_identity(&self) -> Result<Principal, AuthError> {
        let socket_path = self.config.spire_agent_socket_path.clone().ok_or_else(|| {
            AuthError::MissingMetadata(
                "SPIRE agent socket path is not configured for workload identity".to_string(),
            )
        })?;

        let client = SpireWorkloadApiClient::new(socket_path);
        let certs = client.fetch_workload_svid().await?;
        self.validate_spiffe_identity(&certs)
    }

    #[cfg(not(unix))]
    pub async fn current_runtime_identity(&self) -> Result<Principal, AuthError> {
        Err(AuthError::MissingMetadata(
            "SPIRE Workload API over Unix domain sockets is not supported on this platform"
                .to_string(),
        ))
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
        let _expected_spiffe = self.expected_spiffe_uri()?;

        #[cfg(unix)]
        let (cert_pem, trust_pem, key_bytes, spiffe_id) = {
            let socket_path = self.config.spire_agent_socket_path.clone().ok_or_else(|| {
                AuthError::MissingMetadata(
                    "SPIRE agent socket path is not configured for authoritative identity"
                        .to_string(),
                )
            })?;

            let client = SpireWorkloadApiClient::new(socket_path);
            let response = client.fetch_x509_svid_response().await?;
            let exact_match = response
                .svids
                .iter()
                .filter(|svid| svid.spiffe_id == expected_spiffe)
                .collect::<Vec<_>>();

            if exact_match.len() != 1 {
                return Err(AuthError::UntrustedIdentity(format!(
                    "authoritative SPIRE identity mismatch: expected exactly one SVID for '{expected_spiffe}' but found {}",
                    exact_match.len()
                )));
            }

            let svid = exact_match[0];
            let cert_pem = der_to_pem(&svid.x509_svid, "CERTIFICATE");
            let trust_pem = der_to_pem(&svid.bundle, "CERTIFICATE");
            let key_bytes = svid.x509_svid_key.clone();
            self.validate_private_key_matches_cert(&cert_pem, &key_bytes)?;
            self.validate_certificate_chain(&cert_pem, &trust_pem)?;
            let spiffe_id = self.extract_spiffe_uri_from_cert(&cert_pem)?;
            if spiffe_id != expected_spiffe {
                return Err(AuthError::UntrustedIdentity(format!(
                    "authoritative SPIRE SVID mismatch: expected '{expected_spiffe}' but got '{spiffe_id}'"
                )));
            }
            (cert_pem, trust_pem, key_bytes, spiffe_id)
        };

        #[cfg(not(unix))]
        let (cert_pem, trust_pem, key_bytes, spiffe_id) = {
            let cert_pem = self
                .config
                .tls_identity
                .certificate_path
                .as_ref()
                .map(|path| Self::load_pem_from_file(path.clone()))
                .transpose()?
                .ok_or_else(|| {
                    AuthError::MissingMetadata("TLS certificate path is not configured".to_string())
                })?;
            let trust_pem = self
                .config
                .tls_identity
                .trust_bundle_path
                .as_ref()
                .map(|path| Self::load_pem_from_file(path.clone()))
                .transpose()?
                .ok_or_else(|| {
                    AuthError::MissingMetadata(
                        "TLS trust bundle path is not configured".to_string(),
                    )
                })?;
            let key_bytes = self
                .config
                .tls_identity
                .key_path
                .as_ref()
                .map(|path| Self::load_pem_from_file(path.clone()))
                .transpose()?
                .ok_or_else(|| {
                    AuthError::MissingMetadata("TLS private key path is not configured".to_string())
                })?;
            let spiffe_id = self.extract_spiffe_uri_from_cert(&cert_pem)?;
            (cert_pem, trust_pem, key_bytes, spiffe_id)
        };

        self.validate_certificate_chain(&cert_pem, &trust_pem)?;
        self.validate_private_key_matches_cert(&cert_pem, &key_bytes)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let not_before = now - 60;
        let not_after = now + 86400;
        let generation = now as u64;

        Ok(crate::domain::auth::TlsIdentitySnapshot {
            certificate_chain_pem: cert_pem,
            private_key: crate::domain::crypto::SecretBytes::new(key_bytes),
            trust_bundle_pem: trust_pem,
            spiffe_id,
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

fn load_trust_anchors(
    trust_bundle_pem: &[u8],
) -> Result<Vec<rustls::pki_types::TrustAnchor<'static>>, AuthError> {
    let certs: Vec<_> = CertificateDer::pem_slice_iter(trust_bundle_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| AuthError::UntrustedIdentity(format!("invalid trust bundle PEM: {err}")))?;

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
        let result = provider
            .extract_spiffe_uri_from_cert(CERT_PEM.as_bytes())
            .unwrap();
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

        let err = provider
            .validate_spiffe_identity(CERT_PEM.as_bytes())
            .unwrap_err();
        assert!(matches!(
            err,
            crate::domain::auth::AuthError::UntrustedIdentity(_)
        ));
    }
}
