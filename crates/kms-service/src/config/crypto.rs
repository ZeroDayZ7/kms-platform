use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::ops::Deref;

// --- TYPY DEDYKOWANE (NewTypes z walidacją) ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterKeyB64(pub String);

impl Deref for MasterKeyB64 {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'de> Deserialize<'de> for MasterKeyB64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = BASE64
            .decode(&s)
            .map_err(|_| serde::de::Error::custom("master_key must be a valid Base64 string"))?;

        if decoded.len() != 32 {
            return Err(serde::de::Error::custom(
                "master_key after Base64 decoding must be exactly 32 bytes (256-bit key for AES-256-GCM)",
            ));
        }

        Ok(MasterKeyB64(s))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyTtlDays(pub u64);

impl Deref for KeyTtlDays {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'de> Deserialize<'de> for KeyTtlDays {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = u64::deserialize(deserializer)?;
        if !(1..=3650).contains(&val) {
            return Err(serde::de::Error::custom(
                "key_ttl_days must be between 1 and 3650 days",
            ));
        }
        Ok(KeyTtlDays(val))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GracePeriodMinutes(pub i64);

impl Deref for GracePeriodMinutes {
    type Target = i64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'de> Deserialize<'de> for GracePeriodMinutes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = i64::deserialize(deserializer)?;
        if !(1..=10_080).contains(&val) {
            return Err(serde::de::Error::custom(
                "grace_period_minutes must be between 1 and 10080 minutes (max 7 days)",
            ));
        }
        Ok(GracePeriodMinutes(val))
    }
}

// --- GŁÓWNA STRUKTURA KONFIGURACJI KMS Z WERSJONOWANIEM ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MasterKeyProvider {
    #[default]
    Local,
    Hsm,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CryptoSettings {
    #[serde(default)]
    pub provider: MasterKeyProvider,
    #[serde(default)]
    pub hsm_socket_path: Option<String>,
    pub current_master_key_version: i32,
    pub master_keys: HashMap<i32, MasterKeyB64>,
    pub default_key_ttl_days: KeyTtlDays,
    pub grace_period_minutes: GracePeriodMinutes,
    #[serde(default)]
    pub enable_http_rewrap: bool,
    #[serde(default)]
    pub enable_http_lock: bool,
}

impl CryptoSettings {
    /// Zwraca klucz główny dla aktywnej wersji
    pub fn current_master_key(&self) -> Option<&MasterKeyB64> {
        self.master_keys.get(&self.current_master_key_version)
    }

    /// Zwraca klucz główny dla podanej wersji
    pub fn get_master_key(&self, version: i32) -> Option<&MasterKeyB64> {
        self.master_keys.get(&version)
    }

    pub fn effective_hsm_socket_path(&self) -> String {
        self.hsm_socket_path
            .clone()
            .unwrap_or_else(|| "/run/vhsm/vhsm.sock".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn provider_defaults_to_local() {
        let provider = MasterKeyProvider::default();
        assert_eq!(provider, MasterKeyProvider::Local);
    }

    #[test]
    fn hsm_mode_requires_existing_socket() {
        let socket = PathBuf::from("/tmp/does-not-exist-vhsm.sock");
        let settings = CryptoSettings {
            provider: MasterKeyProvider::Hsm,
            hsm_socket_path: Some(socket.to_string_lossy().to_string()),
            current_master_key_version: 1,
            master_keys: HashMap::from([(
                1,
                MasterKeyB64("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=".to_string()),
            )]),
            default_key_ttl_days: KeyTtlDays(30),
            grace_period_minutes: GracePeriodMinutes(10),
            enable_http_rewrap: false,
            enable_http_lock: false,
        };

        let err = crate::infrastructure::crypto::kms_service::KmsCryptoService::new(&settings);
        assert!(matches!(err, Err(crate::errors::AppError::ConfigError(_))));
    }
}
