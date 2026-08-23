// region: Imports
use crate::domain::crypto::SecretBytes;
use crate::domain::keys::models::{KeyAlgorithm, ServiceId};
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
// endregion

fn deserialize_secret<'de, D>(deserializer: D) -> Result<SecretBytes, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    Ok(SecretBytes::new(value.into_bytes()))
}

// region: Enums & Models
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum KeyAccessLevel {
    PrivateKey,
    PublicKey,
    #[serde(alias = "SecretKey")]
    SymmetricKey,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AccessRule {
    pub target_service: ServiceId,
    pub algorithm: KeyAlgorithm,
    pub access_level: KeyAccessLevel,
    #[serde(default)]
    pub preload: bool,
}

#[derive(Debug, Deserialize)]
pub struct ServiceConfig {
    pub service_id: ServiceId,
    #[serde(deserialize_with = "deserialize_secret")]
    pub secret: SecretBytes,
    pub allowed_access: Vec<AccessRule>,
    pub allowed_actions: Option<Vec<ControlAction>>,
}

impl Clone for ServiceConfig {
    fn clone(&self) -> Self {
        Self {
            service_id: self.service_id.clone(),
            secret: SecretBytes::new(self.secret.as_bytes().to_vec()),
            allowed_access: self.allowed_access.clone(),
            allowed_actions: self.allowed_actions.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum ControlAction {
    GenerateKeys,
    RotateOwnKeys,
    RotateAllKeys,
    RevokeKeys,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct AclSettings {
    pub services: HashMap<String, ServiceConfig>,
}
// endregion

// region: Implementation
impl AclSettings {
    pub fn is_allowed(
        &self,
        caller: &ServiceId,
        target: &ServiceId,
        algorithm: KeyAlgorithm,
        requested_access: &KeyAccessLevel,
    ) -> bool {
        let Some(service_cfg) = self.services.get(&caller.0) else {
            return false;
        };

        service_cfg.allowed_access.iter().any(|rule| {
            rule.target_service == *target
                && rule.algorithm == algorithm
                && rule.access_level == *requested_access
        })
    }

    pub fn should_preload_for(&self, target: &ServiceId, algorithm: KeyAlgorithm) -> bool {
        self.services.values().any(|service_cfg| {
            service_cfg.allowed_access.iter().any(|rule| {
                rule.target_service == *target && rule.algorithm == algorithm && rule.preload
            })
        })
    }

    pub fn has_control_action(&self, caller: &ServiceId, action: &ControlAction) -> bool {
        let Some(service_cfg) = self.services.get(&caller.0) else {
            return false;
        };

        service_cfg
            .allowed_actions
            .as_ref()
            .is_some_and(|actions| actions.contains(action))
    }
}
// endregion
