use crate::application::use_cases::{
    DecryptDataUseCase, EncryptDataUseCase, GenerateKeyPairUseCase, GetPrivateKeyUseCase,
    GetPublicKeyUseCase, GetSymmetricKeyUseCase, RotateKeyUseCase, SignDataUseCase,
};
use crate::config::Settings;
use crate::domain::rate_limiter::{InMemoryRateLimiter, RateLimiter};
use crate::errors::AppResult;
use crate::infrastructure::crypto::kms_service::VhsmCryptoService;
use crate::infrastructure::crypto::vhsm_client::VhsmClient;
use crate::infrastructure::mongodb::audit::MongoAuditRepository;
use crate::infrastructure::mongodb::client::init_mongo;
use crate::infrastructure::mongodb::keys::MongoKeyRepository;
use crate::infrastructure::redis::client::RedisManager;
use crate::infrastructure::redis::rate_limiter::RedisRateLimiter;
use mongodb::Database;
use std::sync::Arc;

pub type ConcreteEncryptDataUseCase = EncryptDataUseCase<VhsmCryptoService>;
pub type ConcreteDecryptDataUseCase = DecryptDataUseCase<VhsmCryptoService>;
pub type ConcreteGenerateKeyPairUseCase = GenerateKeyPairUseCase<MongoKeyRepository>;
pub type ConcreteGetPublicKeyUseCase = GetPublicKeyUseCase<MongoKeyRepository>;
pub type ConcreteGetPrivateKeyUseCase =
    GetPrivateKeyUseCase<MongoKeyRepository, MongoAuditRepository>;
pub type ConcreteGetSymmetricKeyUseCase =
    GetSymmetricKeyUseCase<MongoKeyRepository, MongoAuditRepository>;
pub type ConcreteRotateKeyUseCase = RotateKeyUseCase<MongoKeyRepository, MongoAuditRepository>;
pub type ConcreteSignDataUseCase = SignDataUseCase<MongoKeyRepository, MongoAuditRepository>;

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
    pub db: Database,
    pub redis_manager: Option<Arc<RedisManager>>,
    pub key_repo: Arc<MongoKeyRepository>,
    pub crypto_service: Arc<VhsmCryptoService>,
}

impl AppState {
    pub async fn new(settings: Arc<Settings>) -> AppResult<Self> {
        let mongo_db = init_mongo(&settings.database).await?;

        let redis_manager = if settings.redis.enabled {
            Some(Arc::new(RedisManager::new(&settings.redis).await?))
        } else {
            None
        };

        let rate_limiter: Arc<dyn RateLimiter> = match redis_manager.as_ref() {
            Some(redis) => Arc::new(RedisRateLimiter::new(redis.clone()).await),
            None => Arc::new(InMemoryRateLimiter::new()),
        };

        let db_pool = Arc::new(mongo_db.clone());

        let key_repo = Arc::new(MongoKeyRepository::new(Arc::clone(&db_pool)));
        let audit_repo = Arc::new(MongoAuditRepository::new(&mongo_db));

        key_repo.ensure_indexes().await?;

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
            Arc::new(settings.acl.clone()),
        ));
        let get_public_key_use_case = Arc::new(GetPublicKeyUseCase::new(key_repo.clone()));

        let get_private_key_use_case = Arc::new(GetPrivateKeyUseCase::new(
            key_repo.clone(),
            audit_repo.clone(),
            crypto_service.clone(),
            Arc::new(settings.acl.clone()),
        ));

        let get_symmetric_key_use_case = Arc::new(GetSymmetricKeyUseCase::new(
            key_repo.clone(),
            audit_repo.clone(),
            crypto_service.clone(),
            Arc::new(settings.acl.clone()),
        ));

        let rotate_key_use_case = Arc::new(RotateKeyUseCase::new(
            key_repo.clone(),
            crypto_service.clone(),
            audit_repo.clone(),
            settings.crypto.grace_period_minutes,
            Arc::new(settings.acl.clone()),
        ));

        let sign_data_use_case = Arc::new(SignDataUseCase::new(
            key_repo.clone(),
            audit_repo.clone(),
            crypto_service.clone(),
            Arc::new(settings.acl.clone()),
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
            db: mongo_db,
            redis_manager,
            key_repo,
            crypto_service,
        })
    }
}
