use crate::errors::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IamStatement {
    pub sid: String,
    pub effect: String,
    pub roles: Vec<String>,
    pub actions: Vec<String>,
    pub resources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IamCredentialPolicy {
    pub version: String,
    pub statements: Vec<IamStatement>,
}

impl IamCredentialPolicy {
    pub fn default_policy_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("config")
            .join("iam_credentials_policy.json")
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> AppResult<Self> {
        let path_ref = path.as_ref();
        let content = fs::read_to_string(path_ref).map_err(|e| {
            AppError::Internal(format!(
                "Failed to read IAM policy file '{}': {e}",
                path_ref.display()
            ))
        })?;

        let policy: Self = serde_json::from_str(&content)
            .map_err(|e| AppError::Internal(format!("Failed to parse IAM policy JSON: {e}")))?;

        Ok(policy)
    }

    pub fn load_default() -> AppResult<Self> {
        Self::load_from_file(Self::default_policy_path())
    }

    pub fn is_action_allowed(&self, role: &str, action: &str, resource: &str) -> bool {
        for stmt in &self.statements {
            if stmt.effect != "Allow" {
                continue;
            }

            let role_matches = stmt.roles.iter().any(|r| r == "*" || r == role);
            if !role_matches {
                continue;
            }

            let action_matches = stmt.actions.iter().any(|a| match_pattern(a, action));
            if !action_matches {
                continue;
            }

            let resource_matches = stmt.resources.iter().any(|r| match_pattern(r, resource));
            if resource_matches {
                return true;
            }
        }
        false
    }
}

/// Dynamiczny matcher wspierający wildcard `*` na końcu lub jako pełny zamiennik
fn match_pattern(pattern: &str, candidate: &str) -> bool {
    if pattern == "*" || pattern == candidate {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return candidate.starts_with(prefix);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::IamCredentialPolicy;

    #[test]
    fn parses_default_policy_and_allows_provision() {
        let policy = IamCredentialPolicy::load_default().expect("default IAM policy should parse");
        assert_eq!(policy.version, "2026-08-29");
        assert!(policy.is_action_allowed(
            "provisioner-service",
            "kms:credentials:provision",
            "arn:kms:postgres:db-auth",
        ));
        assert!(!policy.is_action_allowed(
            "provisioner-service",
            "kms:credentials:delete",
            "arn:kms:postgres:db-auth",
        ));
    }
}
