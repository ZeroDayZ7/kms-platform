use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kms_core::hsm::client::HsmClientError;
use serde::Serialize;
use std::borrow::Cow;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Autoryzacja nie powiodła się")]
    Unauthorized,

    #[error("Brak uprawnień do wykonania tej akcji")]
    Forbidden,

    #[error("Nie znaleziono zasobu: {0}")]
    NotFound(String),

    #[error("Błędne dane wejściowe: {0}")]
    ValidationError(String),

    #[error("Błąd kryptograficzny: {0}")]
    CryptoError(String),

    #[error("Błąd bazy danych: {0}")]
    DatabaseError(String),

    #[error("Błąd usługi Redis")]
    RedisError(#[from] fred::error::Error),

    #[error("Błąd komunikacji z HSM: {0}")]
    HsmError(#[from] HsmClientError),

    #[error("Błąd timeout")]
    TimeoutError,

    #[error("Błąd konfiguracji: {0}")]
    ConfigError(String),

    #[error("Błąd serializacji/deserializacji: {0}")]
    SerializationError(String),

    #[error("Błąd środowiska wykonawczego: {0}")]
    RuntimeError(String),

    #[error("Zasób w konflikcie: {0}")]
    Conflict(String),

    #[error("Błąd zewnętrznej usługi (HTTP): {0}")]
    ExternalServiceError(String),

    #[error("Wystąpił nieoczekiwany błąd serwera: {0}")]
    Internal(String),
}

impl From<serde_json::Error> for AppError {
    //#region from
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

impl From<anyhow::Error> for AppError {
    //#region from
    fn from(err: anyhow::Error) -> Self {
        Self::RuntimeError(err.to_string())
    }
}

impl From<sqlx::Error> for AppError {
    //#region from
    fn from(err: sqlx::Error) -> Self {
        Self::DatabaseError(err.to_string())
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: Cow<'static, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

impl AppError {
    //#region error_code
    fn error_code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Forbidden => "FORBIDDEN",
            Self::NotFound(_) => "RESOURCE_NOT_FOUND",
            Self::ValidationError(_) => "VALIDATION_ERROR",
            Self::Conflict(_) => "CONFLICT_ERROR",
            Self::CryptoError(_) => "CRYPTO_FAILURE",
            Self::DatabaseError(_) => "INTERNAL_SERVER_ERROR",
            Self::RedisError(_) => "INTERNAL_SERVER_ERROR",
            Self::HsmError(_) => "HSM_COMMUNICATION_ERROR",
            Self::TimeoutError => "TIMEOUT_ERROR",
            Self::ConfigError(_) => "CONFIG_INVALID",
            Self::SerializationError(_) => "VALIDATION_ERROR",
            Self::ExternalServiceError(_) => "EXTERNAL_SERVICE_UNAVAILABLE",
            Self::RuntimeError(_) => "INTERNAL_SERVER_ERROR",
            Self::Internal(_) => "INTERNAL_SERVER_ERROR",
        }
    }

    //#region public_message
    fn public_message(&self) -> Cow<'static, str> {
        match self {
            Self::Unauthorized => "Authentication failed".into(),
            Self::Forbidden => "Forbidden".into(),
            Self::NotFound(_) => "Resource not found".into(),
            Self::ValidationError(_) => "Invalid request".into(),
            Self::Conflict(_) => "Resource conflict".into(),
            Self::CryptoError(_) => "Cryptographic operation failed".into(),
            Self::DatabaseError(_) => "Internal server error".into(),
            Self::RedisError(_) => "Internal server error".into(),
            Self::HsmError(_) => "HSM communication error".into(),
            Self::TimeoutError => "Request timed out".into(),
            Self::ConfigError(_) => "Configuration error".into(),
            Self::SerializationError(_) => "Invalid request".into(),
            Self::ExternalServiceError(_) => "External service unavailable".into(),
            Self::RuntimeError(_) => "Internal server error".into(),
            Self::Internal(_) => "Internal server error".into(),
        }
    }
}

impl IntoResponse for AppError {
    //#region into_response
    fn into_response(self) -> Response {
        let code = self.error_code();
        let public_message = self.public_message();

        let status = match &self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::ValidationError(_) => StatusCode::BAD_REQUEST,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::CryptoError(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::DatabaseError(err) => {
                tracing::error!(target: "infra::db", error = ?err, "Database Error");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::RedisError(err) => {
                tracing::error!(target: "infra::redis", error = ?err, "Redis Error");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::HsmError(err) => {
                tracing::error!(target: "infra::hsm", error = ?err, "HSM Error");
                StatusCode::BAD_GATEWAY
            }
            Self::SerializationError(err) => {
                tracing::warn!(error = ?err, "JSON Serialization failed");
                StatusCode::BAD_REQUEST
            }
            Self::ConfigError(err) => {
                tracing::error!(error = ?err, "Critical configuration error!");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::ExternalServiceError(err) => {
                tracing::error!(error = ?err, "External service call failed");
                StatusCode::BAD_GATEWAY
            }
            Self::RuntimeError(err) => {
                tracing::error!(error = ?err, "Runtime execution error");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::Internal(err) => {
                tracing::error!(error = ?err, "Unexpected Internal Error");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::TimeoutError => StatusCode::REQUEST_TIMEOUT,
        };

        let body = Json(ErrorResponse {
            code,
            message: public_message,
            request_id: None,
        });

        (status, body).into_response()
    }
}

impl From<tokio::time::error::Elapsed> for AppError {
    //#region from
    fn from(_: tokio::time::error::Elapsed) -> Self {
        Self::TimeoutError
    }
}
