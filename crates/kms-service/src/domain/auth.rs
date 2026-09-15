use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Principal {
    pub subject: String,
    pub kind: PrincipalKind,
    pub attributes: BTreeMap<String, String>,
}

impl Principal {
    pub fn service(service_id: impl Into<String>) -> Self {
        Self {
            subject: service_id.into(),
            kind: PrincipalKind::Service,
            attributes: BTreeMap::new(),
        }
    }

    pub fn spiffe(uri: impl Into<String>) -> Self {
        Self {
            subject: uri.into(),
            kind: PrincipalKind::Spiffe,
            attributes: BTreeMap::new(),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.subject
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationContext {
    pub principal: Principal,
    pub authentication_method: AuthenticationMethod,
    pub metadata: BTreeMap<String, String>,
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

pub trait Authenticator: Send + Sync {
    fn authenticate(
        &self,
        subject: &str,
        metadata: &BTreeMap<String, String>,
    ) -> Result<AuthenticationContext, String>;
}

#[derive(Debug, Clone, Default)]
pub struct HmacAuthenticator;

impl Authenticator for HmacAuthenticator {
    fn authenticate(
        &self,
        subject: &str,
        metadata: &BTreeMap<String, String>,
    ) -> Result<AuthenticationContext, String> {
        Ok(AuthenticationContext {
            principal: Principal::service(subject),
            authentication_method: AuthenticationMethod::Hmac,
            metadata: metadata.clone(),
        })
    }
}
