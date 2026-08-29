use std::collections::HashMap;
use std::sync::Arc;

use super::{TargetResourceProvider, postgres::PostgresTargetProvider};
use crate::errors::AppError;

pub struct ProviderFactory {
    providers: HashMap<String, Arc<dyn TargetResourceProvider>>,
}

impl ProviderFactory {
    pub fn new() -> Self {
        let mut providers: HashMap<String, Arc<dyn TargetResourceProvider>> = HashMap::new();

        // Rejestracja dostępnych providerów
        providers.insert("postgres".to_string(), Arc::new(PostgresTargetProvider));
        // providers.insert("rabbitmq".to_string(), Arc::new(RabbitMqTargetProvider));
        // providers.insert("minio".to_string(), Arc::new(MinioTargetProvider));

        Self { providers }
    }

    pub fn get(&self, target_type: &str) -> Result<Arc<dyn TargetResourceProvider>, AppError> {
        self.providers.get(target_type).cloned().ok_or_else(|| {
            AppError::NotFound(format!("Unsupported provider type: {}", target_type))
        })
    }
}

impl Default for ProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}
