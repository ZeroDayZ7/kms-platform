use std::collections::HashMap;
use std::sync::Arc;

use super::{TargetResourceProvider, postgres::PostgresTargetProvider, redis::RedisTargetProvider};
use crate::errors::AppError;
use crate::config::ProvidersAclSettings;

pub struct ProviderFactory {
    providers: HashMap<String, Arc<dyn TargetResourceProvider>>,
}

impl ProviderFactory {
    pub fn new(providers_acl: Arc<ProvidersAclSettings>) -> Self {
        let mut providers: HashMap<String, Arc<dyn TargetResourceProvider>> = HashMap::new();

        providers.insert("postgres".to_string(), Arc::new(PostgresTargetProvider));
        providers.insert(
            "redis".to_string(),
            Arc::new(RedisTargetProvider::new(providers_acl)),
        );
        // providers.insert("rabbitmq".to_string(), Arc::new(RabbitMqTargetProvider));
        // providers.insert("minio".to_string(), Arc::new(MinioTargetProvider));

        Self { providers }
    }

    pub fn get(&self, target_type: &str) -> Result<Arc<dyn TargetResourceProvider>, AppError> {
        let normalized_type = target_type.to_lowercase();

        self.providers
            .get(&normalized_type)
            .cloned()
            .ok_or_else(|| {
                AppError::NotFound(format!("Unsupported provider type: {}", target_type))
            })
    }
}

impl Default for ProviderFactory {
    fn default() -> Self {
        Self::new(Arc::new(ProvidersAclSettings::default()))
    }
}
