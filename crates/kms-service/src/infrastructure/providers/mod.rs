pub mod factory;
pub mod minio;
pub mod postgres;
pub mod rabbitmq;

use crate::errors::AppError;
use async_trait::async_trait;

pub use factory::ProviderFactory;

pub struct GeneratedCredential {
    pub username: String,
    pub secret: String,
    pub ttl_seconds: i64,
}

#[async_trait]
pub trait TargetResourceProvider: Send + Sync {
    async fn create_user(
        &self,
        target_conn_str: &str,
        role: &str,
        ttl_seconds: i64,
    ) -> Result<GeneratedCredential, AppError>;

    async fn revoke_user(&self, target_conn_str: &str, username: &str) -> Result<(), AppError>;
}
