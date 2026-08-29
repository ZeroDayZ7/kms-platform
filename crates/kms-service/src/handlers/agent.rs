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
