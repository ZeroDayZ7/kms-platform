use std::collections::BTreeMap;

use crate::domain::crypto::SecretBytes;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthenticationMethod {
    Hmac,
    Spiffe,
    Mtls,
    Legacy,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrincipalKind {
    Service,
    Spiffe,
    Mtls,
    Operator,
    System,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Principal {
    Service {
        id: String,
        attributes: BTreeMap<String, String>,
    },
    Spiffe {
        uri: String,
        attributes: BTreeMap<String, String>,
    },
    Operator {
        id: String,
        attributes: BTreeMap<String, String>,
    },
    System {
        id: String,
        attributes: BTreeMap<String, String>,
    },
    Unknown {
        subject: String,
        attributes: BTreeMap<String, String>,
    },
}

impl Principal {
    pub fn service(service_id: impl Into<String>) -> Self {
        Self::Service {
            id: service_id.into(),
            attributes: BTreeMap::new(),
        }
    }

    pub fn spiffe(uri: impl Into<String>) -> Self {
        Self::Spiffe {
            uri: uri.into(),
            attributes: BTreeMap::new(),
        }
    }

    pub fn operator(id: impl Into<String>) -> Self {
        Self::Operator {
            id: id.into(),
            attributes: BTreeMap::new(),
        }
    }

    pub fn system(id: impl Into<String>) -> Self {
        Self::System {
            id: id.into(),
            attributes: BTreeMap::new(),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Service { id, .. }
            | Self::Operator { id, .. }
            | Self::System { id, .. }
            | Self::Unknown { subject: id, .. } => id,
            Self::Spiffe { uri, .. } => uri,
        }
    }

    pub fn kind(&self) -> PrincipalKind {
        match self {
            Self::Service { .. } => PrincipalKind::Service,
            Self::Spiffe { .. } => PrincipalKind::Spiffe,
            Self::Operator { .. } => PrincipalKind::Operator,
            Self::System { .. } => PrincipalKind::System,
            Self::Unknown { .. } => PrincipalKind::Other,
        }
    }
}

impl From<&str> for Principal {
    fn from(value: &str) -> Self {
        Self::service(value)
    }
}

impl From<String> for Principal {
    fn from(value: String) -> Self {
        Self::service(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationContext {
    pub principal: Principal,
    pub authentication_method: AuthenticationMethod,
    pub metadata: BTreeMap<String, String>,
    pub request_id: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationContext {
    pub principal: Option<Principal>,
    pub operation: String,
    pub key_id: Option<String>,
    pub key_version: Option<u32>,
    pub request_id: Option<String>,
    pub operation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum AuthError {
    #[error("authentication failed: {0}")]
    Failed(String),
    #[error("identity is not trusted: {0}")]
    UntrustedIdentity(String),
    #[error("missing identity metadata: {0}")]
    MissingMetadata(String),
}

#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(
        &self,
        subject: &str,
        metadata: &BTreeMap<String, String>,
    ) -> Result<AuthenticationContext, AuthError>;
}

#[derive(Debug, Clone, Default)]
pub struct HmacAuthenticator;

#[async_trait]
impl Authenticator for HmacAuthenticator {
    async fn authenticate(
        &self,
        subject: &str,
        metadata: &BTreeMap<String, String>,
    ) -> Result<AuthenticationContext, AuthError> {
        Ok(AuthenticationContext {
            principal: Principal::service(subject),
            authentication_method: AuthenticationMethod::Hmac,
            metadata: metadata.clone(),
            request_id: metadata.get("request_id").cloned(),
            session_id: metadata.get("session_id").cloned(),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpiffeAuthenticator;

#[async_trait]
impl Authenticator for SpiffeAuthenticator {
    async fn authenticate(
        &self,
        subject: &str,
        metadata: &BTreeMap<String, String>,
    ) -> Result<AuthenticationContext, AuthError> {
        if subject.trim().is_empty() {
            return Err(AuthError::Failed("empty SPIFFE subject".to_string()));
        }

        let mut principal_metadata = metadata.clone();
        principal_metadata.insert("identity_source".to_string(), "spiffe".to_string());

        Ok(AuthenticationContext {
            principal: Principal::spiffe(subject),
            authentication_method: AuthenticationMethod::Spiffe,
            metadata: principal_metadata,
            request_id: metadata.get("request_id").cloned(),
            session_id: metadata.get("session_id").cloned(),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct MtlsAuthenticator;

#[async_trait]
impl Authenticator for MtlsAuthenticator {
    async fn authenticate(
        &self,
        subject: &str,
        metadata: &BTreeMap<String, String>,
    ) -> Result<AuthenticationContext, AuthError> {
        if subject.trim().is_empty() {
            return Err(AuthError::UntrustedIdentity(
                "empty mTLS peer identity".to_string(),
            ));
        }

        Ok(AuthenticationContext {
            principal: Principal::spiffe(subject),
            authentication_method: AuthenticationMethod::Mtls,
            metadata: metadata.clone(),
            request_id: metadata.get("request_id").cloned(),
            session_id: metadata.get("session_id").cloned(),
        })
    }
}

// Configuration-level TLS identity (file paths / admin-configured)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsIdentity {
    pub certificate_path: Option<String>,
    pub key_path: Option<String>,
    pub trust_bundle_path: Option<String>,
    pub workload_id: Option<String>,
    pub spiffe_id: Option<String>,
}

// Runtime immutable identity snapshot containing the complete SVID, private key (secret), and trust bundle.
#[derive(Clone)]
pub struct TlsIdentitySnapshot {
    // PEM-encoded certificate chain (leaf first)
    pub certificate_chain_pem: Vec<u8>,
    // Private key bytes kept in a secret wrapper
    pub private_key: SecretBytes,
    // PEM-encoded trust bundle
    pub trust_bundle_pem: Vec<u8>,
    // SPIFFE ID extracted from cert
    pub spiffe_id: String,
    // validity window (unix seconds)
    pub not_before: i64,
    pub not_after: i64,
    // monotonic generation/version for auditing
    pub generation: u64,
}

impl std::fmt::Debug for TlsIdentitySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsIdentitySnapshot")
            .field("spiffe_id", &self.spiffe_id)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("generation", &self.generation)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkloadIdentityConfig {
    pub enabled: bool,
    pub trust_domain: Option<String>,
    pub workload_id: Option<String>,
    pub spire_agent_socket_path: Option<String>,
    pub tls_identity: TlsIdentity,
    pub rotation_interval_secs: u64,
}

#[async_trait]
pub trait WorkloadIdentityProvider: Send + Sync {
    async fn current_principal(&self) -> Result<Principal, AuthError>;
    /// Return the configured TLS identity (paths/config) when applicable.
    async fn tls_identity(&self) -> Result<TlsIdentity, AuthError>;
    /// Atomically fetch a complete runtime identity snapshot (certificate chain, private key, trust bundle).
    async fn fetch_identity(&self) -> Result<TlsIdentitySnapshot, AuthError>;
}

#[derive(Debug, Clone, Default)]
pub struct IdentityReloader;

impl IdentityReloader {
    pub fn new() -> Self {
        Self
    }

    pub fn should_reload(&self, _current: &TlsIdentity, _next: &TlsIdentity) -> bool {
        true
    }
}
