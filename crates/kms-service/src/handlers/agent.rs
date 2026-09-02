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
    #[serde(default)]
    pub target_service: Option<String>,
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
    tracing::info!(
        caller = %caller.0,
        target_service = %payload.target_service,
        target_type = %payload.target_type,
        resource = %payload.resource,
        ttl_seconds = payload.ttl_seconds,
        "[KMS 1.1] Otrzymano żądanie pojedynczego issue credential"
    );

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
    tracing::info!(
        caller = %caller_service,
        items = payload.credentials.len(),
        ttl_seconds = payload.ttl_seconds,
        "[KMS 2.1] Otrzymano żądanie batch issue credential"
    );

    for (index, item) in payload.credentials.iter().enumerate() {
        let resolved_target_service = item
            .target_service
            .clone()
            .unwrap_or_else(|| item.resource.clone());
        tracing::debug!(
            index = index,
            name = %item.name,
            target_service = %resolved_target_service,
            target_type = %item.r#type,
            resource = %item.resource,
            "[KMS 2.2] Przetwarzanie elementu batch przed ACL"
        );
    }

    let batch_inputs: Vec<_> = payload
        .credentials
        .iter()
        .map(|item| IssueAgentCredentialInput {
            caller_service: caller_service.clone(),
            target_service: item
                .target_service
                .clone()
                .unwrap_or_else(|| item.resource.clone()),
            target_type: item.r#type.clone(),
            resource: item.resource.clone(),
            ttl_seconds: payload.ttl_seconds,
        })
        .collect();

    IssueAgentCredentialUseCase::validate_batch_acl(&state, &batch_inputs)?;

    let mut credentials = HashMap::new();

    for item in payload.credentials {
        let resolved_target_service = item
            .target_service
            .clone()
            .unwrap_or_else(|| item.resource.clone());

        tracing::info!(
            name = %item.name,
            target_service = %resolved_target_service,
            target_type = %item.r#type,
            resource = %item.resource,
            "[KMS 2.3] Uruchamianie wykonania pojedynczego elementu batch"
        );

        let input = IssueAgentCredentialInput {
            caller_service: caller_service.clone(),
            target_service: resolved_target_service.clone(),
            target_type: item.r#type.clone(),
            resource: item.resource.clone(),
            ttl_seconds: payload.ttl_seconds,
        };

        // Zamiast używać `?`, łapiemy wynik, aby go zalogować
        let output_result = IssueAgentCredentialUseCase::execute(&state, input).await;

        match output_result {
            Ok(output) => {
                tracing::info!(
                    name = %item.name,
                    credential_id = %output.credential_id,
                    "[KMS 2.4] Sukces - wygenerowano poświadczenie"
                );
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
            Err(e) => {
                // TUTAJ ZOBACZYSZ DOKŁADNY BŁĄD
                tracing::error!(
                    error = %e,
                    name = %item.name,
                    target_service = %resolved_target_service,
                    resource = %item.resource,
                    "[KMS 2.ERROR] Błąd podczas pobierania/generowania poświadczeń (najpewniej brak rekordu w target_resources)"
                );
                return Err(e); // Zwracamy błąd dalej do Axuma
            }
        }
    }

    Ok(Json(AgentIssueCredentialsBatchResponse { credentials }))
}
