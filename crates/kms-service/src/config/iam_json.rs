use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IamCredentialPolicy {
    pub version: String,
    pub policies: Vec<IamPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IamPolicy {
    pub role: String,
    pub actions: Vec<String>,
    pub resources: Vec<String>,
}

impl IamCredentialPolicy {
    pub fn default_policy_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("config")
            .join("iam_credentials_policy.json")
    }

    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|err| {
            format!(
                "Failed to read IAM policy file '{}': {err}",
                path.as_ref().display()
            )
        })?;

        serde_json::from_str(&content)
            .map_err(|err| format!("Failed to parse IAM policy JSON: {err}"))
    }

    pub fn load_default() -> Result<Self, String> {
        Self::load_from_file(Self::default_policy_path())
    }

    pub fn is_action_allowed(&self, role: &str, action: &str, resource: &str) -> bool {
        self.policies.iter().any(|policy| {
            if policy.role != role {
                return false;
            }

            let matches_action = policy.actions.iter().any(|candidate| candidate == action);
            let matches_resource = policy.resources.iter().any(|candidate| {
                if candidate.ends_with('*') {
                    let prefix = candidate.trim_end_matches('*');
                    return resource.starts_with(prefix);
                }
                candidate == resource
            });

            matches_action && matches_resource
        })
    }
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
