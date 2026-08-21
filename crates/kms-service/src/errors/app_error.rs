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
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        Self::RuntimeError(err.to_string())
    }
}

impl From<mongodb::error::Error> for AppError {
    fn from(err: mongodb::error::Error) -> Self {
        Self::DatabaseError(err.to_string())
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        Self::DatabaseError(err.to_string())
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: Cow<'static, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

impl AppError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "AUTH_FAILED",
            Self::NotFound(_) => "RESOURCE_NOT_FOUND",
            Self::ValidationError(_) => "VALIDATION_ERROR",
            Self::Conflict(_) => "CONFLICT_ERROR",
            Self::CryptoError(_) => "CRYPTO_FAILURE",
            Self::DatabaseError(_) => "DATABASE_ERROR",
            Self::RedisError(_) => "CACHE_ERROR",
            Self::HsmError(_) => "HSM_COMMUNICATION_ERROR",
            Self::TimeoutError => "TIMEOUT_ERROR",
            Self::ConfigError(_) => "CONFIG_INVALID",
            Self::SerializationError(_) => "SERIALIZATION_FAILED",
            Self::ExternalServiceError(_) => "EXTERNAL_SERVICE_UNAVAILABLE",
            Self::RuntimeError(_) => "RUNTIME_ERROR",
            Self::Internal(_) => "INTERNAL_SERVER_ERROR",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let code = self.error_code();
        let message = self.to_string();

        let status = match &self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::ValidationError(_) => StatusCode::BAD_REQUEST,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::CryptoError(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::DatabaseError(err) => {
                tracing::error!(target: "infra::db", %err, "Database Error");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::RedisError(err) => {
                tracing::error!(target: "infra::redis", %err, "Redis Error");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::HsmError(err) => {
                tracing::error!(target: "infra::hsm", %err, "HSM Error");
                StatusCode::BAD_GATEWAY
            }
            Self::SerializationError(err) => {
                tracing::warn!(%err, "JSON Serialization failed");
                StatusCode::BAD_REQUEST
            }
            Self::ConfigError(err) => {
                tracing::error!(%err, "Critical configuration error!");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::ExternalServiceError(err) => {
                tracing::error!(%err, "External service call failed");
                StatusCode::BAD_GATEWAY
            }
            Self::RuntimeError(err) => {
                tracing::error!(%err, "Runtime execution error");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::Internal(err) => {
                tracing::error!(%err, "Unexpected Internal Error");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::TimeoutError => StatusCode::REQUEST_TIMEOUT,
        };

        let body = Json(ErrorResponse {
            code,
            message: message.into(),
            details: match &self {
                Self::ValidationError(d)
                | Self::NotFound(d)
                | Self::CryptoError(d)
                | Self::ConfigError(d)
                | Self::RuntimeError(d)
                | Self::ExternalServiceError(d) => Some(d.clone()),
                Self::HsmError(err) => Some(err.to_string()),
                Self::Internal(d) => Some(d.clone()),
                _ => None,
            },
        });

        (status, body).into_response()
    }
}

impl From<tokio::time::error::Elapsed> for AppError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        Self::TimeoutError
    }
}
