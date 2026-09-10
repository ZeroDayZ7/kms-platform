use axum::{extract::FromRequestParts, http::request::Parts};

use crate::{domain::keys::models::ServiceId, errors::AppError};

pub struct AuthenticatedService(pub ServiceId);

impl<S> FromRequestParts<S> for AuthenticatedService
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<ServiceId>()
            .cloned()
            .map(AuthenticatedService)
            .ok_or(AppError::Unauthorized)
    }
}
