use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

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
}

pub fn compute_audit_hash(input: &AuditHashInput<'_>) -> String {
    let mut record = BTreeMap::new();
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
