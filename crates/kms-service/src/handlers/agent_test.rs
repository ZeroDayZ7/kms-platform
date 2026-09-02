#[cfg(test)]
mod tests {
    use super::{AgentIssueBatchCredentialsRequest, AgentIssueCredentialsBatchResponse};

    #[test]
    fn batch_contract_matches_agent_bootstrap_shape() {
        let json = r#"{
            "credentials": [
                {"name": "postgres", "target_service": "auth_db", "type": "database", "resource": "arn:kms:postgres:db-auth"},
                {"name": "redis", "target_service": "session_cache", "type": "cache", "resource": "arn:kms:redis:session-cache"}
            ],
            "ttl_seconds": 2700
        }"#;

        let request: AgentIssueBatchCredentialsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.credentials.len(), 2);
        assert_eq!(request.credentials[0].name, "postgres");
        assert_eq!(
            request.credentials[0].target_service,
            Some("auth_db".to_string())
        );
        assert_eq!(request.credentials[0].r#type, "database");
        assert_eq!(request.credentials[0].resource, "arn:kms:postgres:db-auth");

        let response = AgentIssueCredentialsBatchResponse {
            credentials: std::collections::HashMap::from([
                (
                    "postgres".to_string(),
                    super::AgentIssueCredentialsResponse {
                        credential_id: uuid::Uuid::new_v4(),
                        username: "kms_auth_auth_db".to_string(),
                        password: "super-secret".to_string(),
                        expires_at: "2025-01-01T00:00:00Z".to_string(),
                    },
                ),
                (
                    "redis".to_string(),
                    super::AgentIssueCredentialsResponse {
                        credential_id: uuid::Uuid::new_v4(),
                        username: "kms_session_cache".to_string(),
                        password: "redis-secret".to_string(),
                        expires_at: "2025-01-01T00:00:00Z".to_string(),
                    },
                ),
            ]),
        };

        let encoded = serde_json::to_string(&response).unwrap();
        assert!(encoded.contains("\"postgres\""));
        assert!(encoded.contains("\"redis\""));
        assert!(encoded.contains("\"password\":\"super-secret\""));
    }
}
