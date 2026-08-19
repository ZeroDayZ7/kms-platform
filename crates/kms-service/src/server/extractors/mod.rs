// src/server/extractors/mod.rs
pub mod authenticated_service;
pub mod validated_id;

pub use authenticated_service::AuthenticatedService;
pub use validated_id::ValidatedId;
