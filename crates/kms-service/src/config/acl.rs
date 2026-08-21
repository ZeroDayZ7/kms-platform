// region: Imports
use crate::domain::keys::models::{KeyAlgorithm, ServiceId};
use serde::Deserialize;
use std::collections::HashMap;
// endregion

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

#[derive(Debug, Deserialize, Clone)]
pub struct ServiceConfig {
    pub service_id: ServiceId,
    pub secret: String,
    pub allowed_access: Vec<AccessRule>,
    pub allowed_actions: Option<Vec<ControlAction>>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum ControlAction {
    GenerateKeys,
    RotateOwnKeys,
    RotateAllKeys,
    RevokeKeys,
}

#[derive(Debug, Deserialize, Clone, Default)]
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
