use std::{collections::BTreeMap, fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditHashVersion {
    #[serde(rename = "v1")]
    V1,
}

impl AuditHashVersion {
    pub const CURRENT: Self = Self::V1;

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
        }
    }
}

impl Default for AuditHashVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

impl fmt::Display for AuditHashVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("Unsupported audit hash version: {0}")]
pub struct AuditHashVersionError(String);

impl FromStr for AuditHashVersion {
    type Err = AuditHashVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "v1" => Ok(Self::V1),
            _ => Err(AuditHashVersionError(s.to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditHashInput<'a> {
    pub id: &'a str,
    pub caller_service: &'a str,
    pub target_service: &'a str,
    pub action: &'a str,
    pub algorithm: &'a str,
    pub status: &'a str,
    pub reason: Option<&'a str>,
    pub prev_hash: &'a str,
    pub timestamp: &'a DateTime<Utc>,
    pub request_id: Option<&'a str>,
    pub operation_id: Option<&'a str>,
    pub target_id: Option<&'a str>,
    pub metadata: Option<&'a str>,
    pub hash_version: AuditHashVersion,
}

pub fn compute_audit_hash(input: &AuditHashInput<'_>) -> String {
    compute_hash_for_version(input.hash_version, input)
}

fn compute_hash_for_version(version: AuditHashVersion, input: &AuditHashInput<'_>) -> String {
    let mut record = BTreeMap::new();

    if version != AuditHashVersion::CURRENT {
        record.insert(
            "hash_version".to_string(),
            Value::String(version.as_str().to_string()),
        );
    }

    record.insert(
        "action".to_string(),
        Value::String(input.action.to_string()),
    );
    record.insert(
        "algorithm".to_string(),
        Value::String(input.algorithm.to_string()),
    );
    record.insert(
        "caller_service".to_string(),
        Value::String(input.caller_service.to_string()),
    );
    record.insert("id".to_string(), Value::String(input.id.to_string()));
    record.insert(
        "prev_hash".to_string(),
        Value::String(input.prev_hash.to_string()),
    );
    record.insert(
        "reason".to_string(),
        match input.reason {
            Some(reason) => Value::String(reason.to_string()),
            None => Value::Null,
        },
    );
    record.insert(
        "status".to_string(),
        Value::String(input.status.to_string()),
    );
    record.insert(
        "target_service".to_string(),
        Value::String(input.target_service.to_string()),
    );
    record.insert(
        "timestamp".to_string(),
        Value::String(input.timestamp.to_rfc3339()),
    );
    record.insert(
        "request_id".to_string(),
        match input.request_id {
            Some(value) => Value::String(value.to_string()),
            None => Value::Null,
        },
    );
    record.insert(
        "operation_id".to_string(),
        match input.operation_id {
            Some(value) => Value::String(value.to_string()),
            None => Value::Null,
        },
    );
    record.insert(
        "target_id".to_string(),
        match input.target_id {
            Some(value) => Value::String(value.to_string()),
            None => Value::Null,
        },
    );
    record.insert(
        "metadata".to_string(),
        match input.metadata {
            Some(value) => Value::String(value.to_string()),
            None => Value::Null,
        },
    );

    let payload = Value::Object(Map::from_iter(record));
    let mut hasher = Sha256::new();
    hasher.update(
        serde_json::to_string(&payload)
            .expect("canonical audit payload must serialize")
            .as_bytes(),
    );
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_hash_version_contract() {
        assert_eq!(AuditHashVersion::CURRENT, AuditHashVersion::V1);
        assert_eq!(AuditHashVersion::V1.as_str(), "v1");
        assert_eq!("v1".parse::<AuditHashVersion>(), Ok(AuditHashVersion::V1));
        assert!("v999".parse::<AuditHashVersion>().is_err());
    }

    #[test]
    fn audit_hash_v1_regression_matches_legacy_payload() {
        let ts = chrono::DateTime::parse_from_rfc3339("2024-01-02T03:04:05Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let input = AuditHashInput {
            id: "audit-123",
            caller_service: "svc-a",
            target_service: "svc-b",
            action: "IssueAgentCredential",
            algorithm: "AES256GCM",
            status: "Success",
            reason: Some("bootstrap import"),
            prev_hash: "0000000000000000000000000000000000000000000000000000000000000000",
            timestamp: &ts,
            request_id: Some("req-88"),
            operation_id: Some("op-42"),
            target_id: Some("target-99"),
            metadata: Some("metadata-value"),
            hash_version: AuditHashVersion::V1,
        };

        let actual = compute_audit_hash(&input);
        assert_eq!(
            actual,
            "0ef537c991c7e85445832d107ca545e8dddc0196c8ac84eba3d3134db845c471"
        );
    }
}
