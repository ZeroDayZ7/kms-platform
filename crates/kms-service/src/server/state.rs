use crate::application::use_cases::{
    DecryptDataUseCase, EncryptDataUseCase, GenerateKeyPairUseCase, GetPrivateKeyUseCase,
    GetPublicKeyUseCase, GetSymmetricKeyUseCase, RotateKeyUseCase, SignDataUseCase,
};
use crate::config::Settings;
use crate::domain::keys::models::{KeyAlgorithm, ServiceId};
use crate::domain::rate_limiter::{InMemoryRateLimiter, RateLimiter};
use crate::errors::AppResult;
use crate::infrastructure::crypto::kms_service::VhsmCryptoService;
use crate::infrastructure::crypto::vhsm_client::VhsmClient;
use crate::infrastructure::postgres::{PgAuditRepository, PgKeyRepository, init_postgres};
use crate::infrastructure::redis::client::RedisManager;
use crate::infrastructure::redis::rate_limiter::RedisRateLimiter;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type ConcreteEncryptDataUseCase = EncryptDataUseCase<VhsmCryptoService>;
pub type ConcreteDecryptDataUseCase = DecryptDataUseCase<VhsmCryptoService>;
pub type ConcreteGenerateKeyPairUseCase = GenerateKeyPairUseCase<PgKeyRepository>;
pub type ConcreteGetPublicKeyUseCase = GetPublicKeyUseCase<PgKeyRepository>;
pub type ConcreteGetPrivateKeyUseCase = GetPrivateKeyUseCase<PgKeyRepository, PgAuditRepository>;
pub type ConcreteGetSymmetricKeyUseCase =
    GetSymmetricKeyUseCase<PgKeyRepository, PgAuditRepository>;
pub type ConcreteRotateKeyUseCase = RotateKeyUseCase<PgKeyRepository, PgAuditRepository>;
pub type ConcreteSignDataUseCase = SignDataUseCase<PgKeyRepository, PgAuditRepository>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyCacheKey {
    pub target_service: String,
    pub algorithm: KeyAlgorithm,
}

#[derive(ZeroizeOnDrop)]
pub struct CachedKeyValue {
    pub version: u32,
    pub bytes: crate::domain::crypto::SecretBytes,
}

#[derive(Clone, Default)]
pub struct KeyCache {
    entries: Arc<RwLock<HashMap<KeyCacheKey, CachedKeyValue>>>,
}

impl KeyCache {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_key<R>(
        &self,
        target_service: &ServiceId,
        algorithm: KeyAlgorithm,
        f: impl FnOnce(u32, &[u8]) -> R,
    ) -> Option<R> {
        let key = KeyCacheKey {
            target_service: target_service.0.clone(),
            algorithm,
        };

        let guard = self.entries.read().ok()?;
        let value = guard.get(&key)?;
        let version = value.version;
        let result = f(version, value.bytes.as_bytes());
        Some(result)
    }

    pub fn insert(
        &self,
        target_service: &ServiceId,
        algorithm: KeyAlgorithm,
        version: u32,
        value: Vec<u8>,
    ) {
        let key = KeyCacheKey {
            target_service: target_service.0.clone(),
            algorithm,
        };

        if let Ok(mut guard) = self.entries.write() {
            guard.insert(
                key,
                CachedKeyValue {
                    version,
                    bytes: crate::domain::crypto::SecretBytes::new(value),
                },
            );
        }
    }

    pub fn remove(&self, target_service: &ServiceId, algorithm: KeyAlgorithm) {
        let key = KeyCacheKey {
            target_service: target_service.0.clone(),
            algorithm,
        };

        if let Ok(mut guard) = self.entries.write()
            && let Some(mut value) = guard.remove(&key)
        {
            value.bytes.zeroize();
        }
    }

    pub fn clear(&self) {
        if let Ok(mut guard) = self.entries.write() {
            for value in guard.values_mut() {
                value.bytes.zeroize();
            }
            guard.clear();
        }
    }
}

pub struct UseCases {
    pub encrypt_data: Arc<ConcreteEncryptDataUseCase>,
    pub decrypt_data: Arc<ConcreteDecryptDataUseCase>,
    pub generate_key_pair: Arc<ConcreteGenerateKeyPairUseCase>,
    pub get_public_key: Arc<ConcreteGetPublicKeyUseCase>,
    pub get_private_key: Arc<ConcreteGetPrivateKeyUseCase>,
    pub get_symmetric_key: Arc<ConcreteGetSymmetricKeyUseCase>,
    pub rotate_key: Arc<ConcreteRotateKeyUseCase>,
    pub sign_data: Arc<ConcreteSignDataUseCase>,
}

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub use_cases: Arc<UseCases>,
    pub rate_limiter: Arc<dyn RateLimiter>,
    pub db: PgPool,
    pub redis_manager: Option<Arc<RedisManager>>,
    pub key_repo: Arc<PgKeyRepository>,
    pub crypto_service: Arc<VhsmCryptoService>,
    pub key_cache: Arc<KeyCache>,
}

impl AppState {
    pub async fn new(settings: Arc<Settings>) -> AppResult<Self> {
        let pg_pool = init_postgres(&settings.database).await?;

        let redis_manager = if settings.redis.enabled {
            Some(Arc::new(RedisManager::new(&settings.redis).await?))
        } else {
            None
        };

        let rate_limiter: Arc<dyn RateLimiter> = match redis_manager.as_ref() {
            Some(redis) => Arc::new(RedisRateLimiter::new(redis.clone()).await),
            None => Arc::new(InMemoryRateLimiter::new()),
        };

        let key_repo = Arc::new(PgKeyRepository::new(pg_pool.clone()));
        let audit_repo = Arc::new(PgAuditRepository::new(pg_pool.clone()));
        let key_cache = Arc::new(KeyCache::new());
        let compiled_acl = Arc::new(settings.acl.compile());

        let vhsm_client = Arc::new(VhsmClient::new(&settings.crypto.hsm_socket_path));
        let crypto_service = Arc::new(VhsmCryptoService::new(vhsm_client));

        let _ =
            crate::workers::expiration::run_expiration_worker(key_repo.clone(), audit_repo.clone())
                .await;

        let encrypt_data_use_case = Arc::new(EncryptDataUseCase::new(crypto_service.clone()));
        let decrypt_data_use_case = Arc::new(DecryptDataUseCase::new(crypto_service.clone()));

        let generate_key_pair_use_case = Arc::new(GenerateKeyPairUseCase::new(
            key_repo.clone(),
            crypto_service.clone(),
            compiled_acl.clone(),
        ));
        let get_public_key_use_case = Arc::new(GetPublicKeyUseCase::new(key_repo.clone()));

        let get_private_key_use_case = Arc::new(GetPrivateKeyUseCase::new(
            key_repo.clone(),
            audit_repo.clone(),
            crypto_service.clone(),
            key_cache.clone(),
            compiled_acl.clone(),
        ));

        let get_symmetric_key_use_case = Arc::new(GetSymmetricKeyUseCase::new(
            key_repo.clone(),
            audit_repo.clone(),
            crypto_service.clone(),
            key_cache.clone(),
            compiled_acl.clone(),
        ));

        let rotate_key_use_case = Arc::new(RotateKeyUseCase::new(
            key_repo.clone(),
            crypto_service.clone(),
            audit_repo.clone(),
            key_cache.clone(),
            settings.crypto.grace_period_minutes,
            compiled_acl.clone(),
        ));

        let sign_data_use_case = Arc::new(SignDataUseCase::new(
            key_repo.clone(),
            audit_repo.clone(),
            crypto_service.clone(),
            key_cache.clone(),
            compiled_acl.clone(),
        ));

        Ok(Self {
            settings,
            use_cases: Arc::new(UseCases {
                encrypt_data: encrypt_data_use_case,
                decrypt_data: decrypt_data_use_case,
                generate_key_pair: generate_key_pair_use_case,
                get_public_key: get_public_key_use_case,
                get_private_key: get_private_key_use_case,
                get_symmetric_key: get_symmetric_key_use_case,
                rotate_key: rotate_key_use_case,
                sign_data: sign_data_use_case,
            }),
            rate_limiter,
            db: pg_pool,
            redis_manager,
            key_repo,
            crypto_service,
            key_cache,
        })
    }

    pub fn clear_key_cache(&self) {
        self.key_cache.clear();
    }
}
