// src/server/extractors/validated_id.rs
use axum::{
    extract::{FromRequestParts, Path},
    http::request::Parts,
};
use uuid::Uuid;

use crate::errors::AppError;

pub struct ValidatedId(pub Uuid);

impl<S> FromRequestParts<S> for ValidatedId
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let path: Path<String> = Path::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::ValidationError("Brak identyfikatora w ścieżce".into()))?;

        let uuid_id = Uuid::parse_str(&path.0).map_err(|_| {
            AppError::ValidationError(format!("Nieprawidłowy format UUID: {}", path.0))
        })?;

        Ok(ValidatedId(uuid_id))
    }
}
