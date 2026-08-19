// src/server/extractors/validated_id.rs
use axum::{
    extract::{FromRequestParts, Path},
    http::request::Parts,
};
use mongodb::bson::oid::ObjectId;

use crate::errors::AppError;

pub struct ValidatedId(pub ObjectId);

impl<S> FromRequestParts<S> for ValidatedId
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let path: Path<String> = Path::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::ValidationError("Brak identyfikatora w ścieżce".into()))?;

        let object_id = ObjectId::parse_str(&path.0).map_err(|_| {
            AppError::ValidationError(format!("Nieprawidłowy format ID: {}", path.0))
        })?;

        Ok(ValidatedId(object_id))
    }
}
