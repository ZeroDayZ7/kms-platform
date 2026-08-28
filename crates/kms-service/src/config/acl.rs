// region: Imports
use crate::domain::crypto::SecretBytes;
use crate::domain::keys::models::{KeyAlgorithm, ServiceId};
use serde::{Deserialize, Deserializer};
use std::collections::{HashMap, HashSet};
// endregion

fn deserialize_secret<'de, D>(deserializer: D) -> Result<SecretBytes, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    Ok(SecretBytes::new(value.into_bytes()))
}

// region: Enums & Models
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAccessLevel {
    PrivateKey,
    PublicKey,
    #[serde(alias = "SecretKey")]
    SymmetricKey,
    GenerateDataKey,
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
    //#region clone
    fn clone(&self) -> Self {
        Self {
            service_id: self.service_id.clone(),
            secret: SecretBytes::new(self.secret.as_bytes().to_vec()),
            allowed_access: self.allowed_access.clone(),
            allowed_actions: self.allowed_actions.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum ControlAction {
    GenerateKeys,
    RotateOwnKeys,
    RotateAllKeys,
    RevokeKeys,
    #[serde(alias = "AuditVerify")]
    AuditVerify,
    #[serde(alias = "AuditRead")]
    AuditRead,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct AclSettings {
    pub services: HashMap<String, ServiceConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccessRuleKey {
    pub caller: ServiceId,
    pub target: ServiceId,
    pub algorithm: KeyAlgorithm,
    pub access_level: KeyAccessLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PreloadKey {
    pub target: ServiceId,
    pub algorithm: KeyAlgorithm,
}

#[derive(Debug, Default, Clone)]
pub struct CompiledAcl {
    pub access: HashSet<AccessRuleKey>,
    pub preload: HashSet<PreloadKey>,
    pub actions: HashMap<String, HashSet<ControlAction>>,
}

impl CompiledAcl {
    //#region is_allowed
    pub fn is_allowed(
        &self,
        caller: &ServiceId,
        target: &ServiceId,
        algorithm: KeyAlgorithm,
        requested_access: KeyAccessLevel,
    ) -> bool {
        self.access.contains(&AccessRuleKey {
            caller: caller.clone(),
            target: target.clone(),
            algorithm,
            access_level: requested_access,
        })
    }

    //#region should_preload_for
    pub fn should_preload_for(&self, target: &ServiceId, algorithm: KeyAlgorithm) -> bool {
        self.preload.contains(&PreloadKey {
            target: target.clone(),
            algorithm,
        })
    }

    //#region has_control_action
    pub fn has_control_action(&self, caller: &ServiceId, action: &ControlAction) -> bool {
        self.actions
            .get(&caller.0)
            .is_some_and(|actions| actions.contains(action))
    }
}

//#region authorize_key_access
pub fn authorize_key_access(
    policy: &CompiledAcl,
    caller: &ServiceId,
    target: &ServiceId,
    algorithm: KeyAlgorithm,
    access: KeyAccessLevel,
) -> bool {
    policy.is_allowed(caller, target, algorithm, access)
}

//#region authorize_control_action
pub fn authorize_control_action(
    policy: &CompiledAcl,
    caller: &ServiceId,
    action: &ControlAction,
) -> bool {
    policy.has_control_action(caller, action)
}
// endregion

// region: Implementation
impl AclSettings {
    //#region compile
    pub fn compile(&self) -> CompiledAcl {
        let mut access = HashSet::new();
        let mut preload = HashSet::new();
        let mut actions = HashMap::new();

        for service_cfg in self.services.values() {
            let service_actions = service_cfg
                .allowed_actions
                .iter()
                .flatten()
                .cloned()
                .collect::<HashSet<_>>();
            actions.insert(service_cfg.service_id.0.clone(), service_actions);

            for rule in &service_cfg.allowed_access {
                access.insert(AccessRuleKey {
                    caller: service_cfg.service_id.clone(),
                    target: rule.target_service.clone(),
                    algorithm: rule.algorithm,
                    access_level: rule.access_level,
                });

                if rule.preload {
                    preload.insert(PreloadKey {
                        target: rule.target_service.clone(),
                        algorithm: rule.algorithm,
                    });
                }
            }
        }

        CompiledAcl {
            access,
            preload,
            actions,
        }
    }

    //#region is_allowed
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

    //#region should_preload_for
    pub fn should_preload_for(&self, target: &ServiceId, algorithm: KeyAlgorithm) -> bool {
        self.services.values().any(|service_cfg| {
            service_cfg.allowed_access.iter().any(|rule| {
                rule.target_service == *target && rule.algorithm == algorithm && rule.preload
            })
        })
    }

    //#region has_control_action
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
