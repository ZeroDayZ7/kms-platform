// src/domain/value_objects/api_route.rs

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiRoute {
    // Operacje kryptograficzne dla mikroserwisów
    EncryptKey,
    DecryptKey,
    SignData,
    VerifySignature,

    // Operacje administracyjne
    KmsRotateMaster,
    KmsRewrap,
    HealthCheck,
}

impl ApiRoute {
    //#region as_str
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EncryptKey => "keys.encrypt",
            Self::DecryptKey => "keys.decrypt",
            Self::SignData => "keys.sign",
            Self::VerifySignature => "keys.verify",
            Self::KmsRotateMaster => "admin.kms.rotate",
            Self::KmsRewrap => "admin.kms.rewrap",
            Self::HealthCheck => "system.health",
        }
    }
}
