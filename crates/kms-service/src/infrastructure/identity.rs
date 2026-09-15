use std::path::Path;

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
        let der = decode_cert_der(cert_bytes)?;
        let mut cursor = 0usize;

        let (_cert_seq, next) = read_der_tlv(&der, 0)?;
        let tbs = find_tbs_certificate_for_cert(&der, next)?;
        for extension in extract_extensions_from_tbs(&tbs)? {
            if extension.oid == [2, 5, 29, 17] {
                for value in parse_subject_alt_name_set(&extension.value)? {
                    if value.starts_with("spiffe://") {
                        return Ok(value);
                    }
                }
            }
        }

        Err(AuthError::UntrustedIdentity(
            "SPIFFE certificate does not contain a valid spiffe:// URI SAN".to_string(),
        ))
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
        let _ = self.extract_spiffe_uri_from_cert(cert_pem)?;
        let bundle = pem::parse_many(trust_bundle_pem).map_err(|err| {
            AuthError::UntrustedIdentity(format!("invalid trust bundle PEM: {err}"))
        })?;
        if bundle.is_empty() {
            return Err(AuthError::UntrustedIdentity(
                "trust bundle is empty; mTLS verification must fail closed".to_string(),
            ));
        }
        Ok(())
    }

    pub fn load_pem_from_file(path: impl AsRef<Path>) -> Result<Vec<u8>, AuthError> {
        std::fs::read(path).map_err(|err| {
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
            .ok_or_else(|| AuthError::MissingMetadata("TLS certificate path is not configured".to_string()))?;
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

fn decode_cert_der(cert_bytes: &[u8]) -> Result<Vec<u8>, AuthError> {
    if let Ok(pem_items) = pem::parse_many(cert_bytes) {
        if let Some(pem) = pem_items.into_iter().next() {
            return Ok(pem.contents);
        }
    }

    if cert_bytes.starts_with(b"-----BEGIN CERTIFICATE-----") {
        return Err(AuthError::UntrustedIdentity(
            "certificate PEM could not be parsed into a valid X.509 block".to_string(),
        ));
    }

    Ok(cert_bytes.to_vec())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DerNode {
    tag: u8,
    value: Vec<u8>,
}

fn read_der_tlv(data: &[u8], offset: usize) -> Result<(DerNode, usize), AuthError> {
    if offset >= data.len() {
        return Err(AuthError::UntrustedIdentity(
            "certificate DER is truncated while reading a TLV node".to_string(),
        ));
    }

    let tag = data[offset];
    let length = if data.get(offset + 1).is_none() {
        return Err(AuthError::UntrustedIdentity(
            "certificate DER is missing a length byte".to_string(),
        ));
    } else {
        let first = data[offset + 1];
        if first & 0x80 == 0 {
            first as usize
        } else {
            let num_bytes = (first & 0x7f) as usize;
            if num_bytes == 0 || offset + 2 + num_bytes > data.len() {
                return Err(AuthError::UntrustedIdentity(
                    "certificate DER length is invalid".to_string(),
                ));
            }
            let mut len = 0usize;
            for b in &data[offset + 2..offset + 2 + num_bytes] {
                len = (len << 8) | (*b as usize);
            }
            len
        }
    };

    let value_start = match tag {
        0x30 | 0x31 | 0xA0 | 0xA1 | 0xA3 => offset + 2 + length_len_for(data, offset + 1),
        _ => offset + 2 + length_len_for(data, offset + 1),
    };

    let value_end = match offset + 1 + length_len_for(data, offset + 1) {
        start if start <= data.len() => start + length,
        _ => return Err(AuthError::UntrustedIdentity("certificate DER layout is malformed".to_string())),
    };

    if value_end > data.len() {
        return Err(AuthError::UntrustedIdentity(
            "certificate DER length exceeds available bytes".to_string(),
        ));
    }

    let value = data[value_start..value_end].to_vec();
    Ok((DerNode { tag, value }, value_end))
}

fn length_len_for(data: &[u8], offset: usize) -> usize {
    let first = data.get(offset).copied().unwrap_or(0);
    if first & 0x80 == 0 {
        1
    } else {
        let len_bytes = (first & 0x7f) as usize;
        len_bytes + 1
    }
}

fn find_tbs_certificate_for_cert(data: &[u8], offset: usize) -> Result<Vec<u8>, AuthError> {
    let (cert_node, _) = read_der_tlv(data, 0)?;
    if cert_node.tag != 0x30 {
        return Err(AuthError::UntrustedIdentity(
            "certificate root node is not a SEQUENCE".to_string(),
        ));
    }
    let mut cursor = 0usize;
    let mut index = 0usize;
    while cursor < cert_node.value.len() {
        let (node, next) = read_der_tlv(&cert_node.value, cursor)?;
        if index == 0 {
            return Ok(node.value);
        }
        cursor = next;
        index += 1;
    }
    Err(AuthError::UntrustedIdentity(
        "certificate is missing the TBS certificate element".to_string(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Extension {
    oid: [u8; 4],
    value: Vec<u8>,
}

fn extract_extensions_from_tbs(tbs: &[u8]) -> Result<Vec<Extension>, AuthError> {
    let (_, mut cursor) = read_der_tlv(tbs, 0)?;
    let mut saw_sequence = false;
    while cursor < tbs.len() {
        let (node, next) = read_der_tlv(tbs, cursor)?;
        if node.tag == 0xA3 {
            saw_sequence = true;
            let inner = parse_extensions_sequence(&node.value)?;
            return Ok(inner);
        }
        cursor = next;
    }
    if saw_sequence {
        return Ok(Vec::new());
    }
    Err(AuthError::UntrustedIdentity(
        "certificate TBS block does not contain X.509 extensions".to_string(),
    ))
}

fn parse_extensions_sequence(data: &[u8]) -> Result<Vec<Extension>, AuthError> {
    let (outer, _) = read_der_tlv(data, 0)?;
    if outer.tag != 0x30 {
        return Err(AuthError::UntrustedIdentity(
            "certificate extensions block is not a SEQUENCE".to_string(),
        ));
    }

    let mut extensions = Vec::new();
    let mut cursor = 0usize;
    while cursor < outer.value.len() {
        let (extension_node, next) = read_der_tlv(&outer.value, cursor)?;
        if extension_node.tag != 0x30 {
            return Err(AuthError::UntrustedIdentity(
                "certificate extension is not a SEQUENCE".to_string(),
            ));
        }

        let mut ext_cursor = 0usize;
        let (oid_node, after_oid) = read_der_tlv(&extension_node.value, ext_cursor)?;
        let oid = oid_node.value;
        let oid_arr = to_oid_array(&oid)?;

        ext_cursor = after_oid;
        let mut critical = false;
        if ext_cursor < extension_node.value.len() {
            let (next_node, next_after) = read_der_tlv(&extension_node.value, ext_cursor)?;
            if next_node.tag == 0x01 {
                critical = next_node.value.first().copied().unwrap_or(0) != 0;
                ext_cursor = next_after;
            } else {
                if next_node.tag != 0x04 {
                    return Err(AuthError::UntrustedIdentity(
                        "unexpected certificate extension format".to_string(),
                    ));
                }
            }
        }

        if ext_cursor >= extension_node.value.len() {
            return Err(AuthError::UntrustedIdentity(
                "certificate extension is missing its value".to_string(),
            ));
        }
        let (value_node, _) = read_der_tlv(&extension_node.value, ext_cursor)?;
        if value_node.tag != 0x04 {
            return Err(AuthError::UntrustedIdentity(
                "certificate extension value is not OCTET STRING".to_string(),
            ));
        }
        extensions.push(Extension { oid: oid_arr, value: value_node.value });
        cursor = next;
    }
    Ok(extensions)
}

fn to_oid_array(bytes: &[u8]) -> Result<[u8; 4], AuthError> {
    if bytes.len() != 6 && bytes.len() != 5 {
        return Err(AuthError::UntrustedIdentity(
            "unsupported X.509 OID length while parsing SPIFFE SAN".to_string(),
        ));
    }
    let mut out = [0u8; 4];
    for (idx, item) in bytes.iter().take(4).enumerate() {
        out[idx] = *item;
    }
    Ok(out)
}

fn parse_subject_alt_name_set(value: &[u8]) -> Result<Vec<String>, AuthError> {
    let (outer, _) = read_der_tlv(value, 0)?;
    if outer.tag != 0x30 {
        return Err(AuthError::UntrustedIdentity(
            "subjectAltName extension value is not a SEQUENCE".to_string(),
        ));
    }

    let mut entries = Vec::new();
    let mut cursor = 0usize;
    while cursor < outer.value.len() {
        let (name, next) = read_der_tlv(&outer.value, cursor)?;
        if name.tag == 0x86 {
            entries.push(String::from_utf8_lossy(&name.value).into_owned());
        }
        cursor = next;
    }
    if entries.is_empty() {
        return Err(AuthError::UntrustedIdentity(
            "subjectAltName extension has no URI values".to_string(),
        ));
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::SpiffeX509IdentityProvider;
    use crate::domain::auth::WorkloadIdentityConfig;

    const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBQzCCATygAwIBAgIBADANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwJ0ZXN0MB4X\nDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowFTETMBEGA1UEAxMKZXhhbXBsZS5v\ncmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCABT8w6XxwH2C3b7yPqLhOMAa3KzZVxVJ\n8YNNm7Y7y7cQ6kXE6Pocd1aXQwHgTsQq9QXxM9Cz9j6oG7U6VJ0mA1j5bw6/6Hplahg\nDwQZsB0wGzAMBgorBgEEAYI3AgEEMH8eW8sZ1j2G7WS65mY4OmMH5W6kM4e0/2x7x1v\n8gN62nR4JbTQ7m5Ps7dS0aE1j3Oh/RbQbElLLxKOuDgkvQfK7h96RltmR9VbLX7B7sU\nWXXVg5f0D0B8FkVt38Jz7qSoa5x0D8u+Y4Ym6LiTVQWJ0UQ6u5FFt8v8ZQbO3UdI2n3\nM8QY8u3sT7qC5m3K7ZV0L7Q5G2B6Yv7EoV0=\n-----END CERTIFICATE-----\n";

    #[test]
    fn parses_spiiffe_uri_san_from_pem() {
        let provider = SpiffeX509IdentityProvider::new(WorkloadIdentityConfig::default());
        let cert = CERT_PEM.as_bytes();

        let result = provider.extract_spiffe_uri_from_cert(cert).unwrap();
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
