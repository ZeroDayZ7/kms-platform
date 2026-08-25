use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

pub use crate::domain::crypto::{EncryptedPrivateKey, KeyAlgorithm, KeyPurpose, SecretBytes};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServiceId(pub String);

impl fmt::Display for ServiceId {
    //#region fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for ServiceId {
    //#region from
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for ServiceId {
    //#region from
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[derive(ZeroizeOnDrop)]
pub struct RawKeyPair {
    pub public_key_pem: String,
    pub private_key_bytes: SecretBytes,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum KeyStatus {
    Active,
    Deprecated { valid_until: DateTime<Utc> },
    Revoked,
    Expired,
    Compromised,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum RotationReason {
    Scheduled,
    Compromised,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPairEntity {
    pub id: Uuid,
    pub service_id: ServiceId,
    pub algorithm: KeyAlgorithm,
    pub purpose: KeyPurpose,
    pub public_key_pem: String,
    pub encrypted_private_key: EncryptedPrivateKey,
    pub version: u32,
    pub status: KeyStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}
