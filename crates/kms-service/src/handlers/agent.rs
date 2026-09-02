use std::collections::HashMap;

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    application::use_cases::{IssueAgentCredentialInput, IssueAgentCredentialUseCase},
    errors::AppResult,
    server::{extractors::authenticated_service::AuthenticatedService, state::AppState},
};

#[derive(Debug, Deserialize)]
pub struct AgentIssueCredentialsRequest {
    pub target_service: String,
    pub target_type: String,
    pub resource: String,
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
}

fn default_ttl() -> u64 {
    2700
}

#[derive(Debug, Serialize)]
pub struct AgentIssueCredentialsResponse {
    pub credential_id: Uuid,
    pub username: String,
    pub password: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BatchCredentialRequestItem {
    pub name: String,
    #[serde(rename = "type")]
    pub r#type: String,
    pub resource: String,
}

#[derive(Debug, Deserialize)]
pub struct AgentIssueBatchCredentialsRequest {
    pub credentials: Vec<BatchCredentialRequestItem>,
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct AgentIssueCredentialsBatchResponse {
    pub credentials: HashMap<String, AgentIssueCredentialsResponse>,
}

#[axum::debug_handler]
pub async fn issue_dynamic_credentials_handler(
    State(state): State<AppState>,
    AuthenticatedService(caller): AuthenticatedService,
    Json(payload): Json<AgentIssueCredentialsRequest>,
) -> AppResult<Json<AgentIssueCredentialsResponse>> {
    let output = IssueAgentCredentialUseCase::execute(
        &state,
        IssueAgentCredentialInput {
            caller_service: caller.0,
            target_service: payload.target_service,
            target_type: payload.target_type,
            resource: payload.resource,
            ttl_seconds: payload.ttl_seconds,
        },
    )
    .await?;

    Ok(Json(AgentIssueCredentialsResponse {
        credential_id: output.credential_id,
        username: output.username,
        password: output.password,
        expires_at: output.expires_at.to_rfc3339(),
    }))
}

#[axum::debug_handler]
pub async fn issue_batch_credentials_handler(
    State(state): State<AppState>,
    AuthenticatedService(caller): AuthenticatedService,
    Json(payload): Json<AgentIssueBatchCredentialsRequest>,
) -> AppResult<Json<AgentIssueCredentialsBatchResponse>> {
    let caller_service = caller.0;
    let mut credentials = HashMap::new();

    for item in payload.credentials {
        let output = IssueAgentCredentialUseCase::execute(
            &state,
            IssueAgentCredentialInput {
                caller_service: caller_service.clone(),
                target_service: item.resource.clone(),
                target_type: item.r#type.clone(),
                resource: item.resource.clone(),
                ttl_seconds: payload.ttl_seconds,
            },
        )
        .await?;

        credentials.insert(
            item.name.clone(),
            AgentIssueCredentialsResponse {
                credential_id: output.credential_id,
                username: output.username,
                password: output.password,
                expires_at: output.expires_at.to_rfc3339(),
            },
        );
    }

    Ok(Json(AgentIssueCredentialsBatchResponse { credentials }))
}

#[cfg(test)]
mod tests {
    use super::{AgentIssueBatchCredentialsRequest, AgentIssueCredentialsBatchResponse};

    #[test]
    fn batch_contract_matches_agent_bootstrap_shape() {
        let json = r#"{
            "credentials": [
                {"name": "postgres", "type": "database", "resource": "auth_db"},
                {"name": "redis", "type": "cache", "resource": "session_cache"}
            ],
            "ttl_seconds": 2700
        }"#;

        let request: AgentIssueBatchCredentialsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.credentials.len(), 2);
        assert_eq!(request.credentials[0].name, "postgres");
        assert_eq!(request.credentials[0].r#type, "database");
        assert_eq!(request.credentials[0].resource, "auth_db");

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
