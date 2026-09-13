use crate::crypto::sss::{KmsCoreError, KmsError};
use getrandom::getrandom;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const KEY_SIZE: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_SIZE]);

impl SecretKey {
    //#region generate
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_SIZE];

        if getrandom(&mut key).is_err() {
            // This is a hard process-level invariant: the OS CSPRNG is required for
            // secret material generation. If the platform RNG is unavailable, the
            // process cannot safely continue and must fail fast without panicking
            // through a Rust `unwrap`/`expect` call.
            tracing::error!("OS RNG failed while generating SecretKey; aborting process");
            std::process::abort();
        }

        Self(key)
    }

    //#region from_bytes
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    //#region as_bytes
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

//#region generate_master_key
pub fn generate_master_key() -> SecretKey {
    SecretKey::generate()
}

//#region generate_secure_secret
/// Generuje kryptograficznie bezpieczny sekret o dowolnej długości (np. poświadczenia, API keys).
pub fn generate_secure_secret(length: usize) -> Result<Zeroizing<Vec<u8>>, KmsError> {
    if length == 0 {
        return Err(KmsCoreError::InvalidInput(
            "Secret length must be greater than zero".to_string(),
        ));
    }
    if length > 4096 {
        return Err(KmsCoreError::InvalidInput(
            "Requested secret length exceeds maximum allowed limit of 4096 bytes".to_string(),
        ));
    }

    let mut buffer = vec![0u8; length];
    getrandom(&mut buffer).map_err(|e| {
        KmsCoreError::Internal(format!("Failed to generate secure random bytes: {e}"))
    })?;

    Ok(Zeroizing::new(buffer))
}
