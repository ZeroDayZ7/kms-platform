use axum::{extract::FromRequestParts, http::request::Parts};

use crate::{
    domain::{auth::Principal, keys::models::ServiceId},
    errors::AppError,
};

pub struct AuthenticatedService(pub ServiceId);
pub struct AuthenticatedPrincipal(pub Principal);

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

impl<S> FromRequestParts<S> for AuthenticatedPrincipal
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Principal>()
            .cloned()
            .map(AuthenticatedPrincipal)
            .ok_or(AppError::Unauthorized)
    }
}
