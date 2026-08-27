use crate::crypto::keys::{KEY_SIZE, SecretKey};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Result, anyhow};
use argon2::{Argon2, password_hash::SaltString};
use getrandom::getrandom;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedContainer {
    pub salt: String,       // Sól dla Argon2
    pub nonce: String,      // IV dla AES-GCM
    pub ciphertext: String, // Zaszyfrowane dane
}

/// Generuje losową sól i derywuje klucz symetryczny AES-256 z podanego hasła (Argon2id)
//#region derive_key_from_password
pub fn derive_key_from_password(password: &str) -> Result<(SecretKey, String)> {
    let mut rng_bytes = [0u8; 16];
    getrandom(&mut rng_bytes).map_err(|e| anyhow!("Nie udało się wygenerować soli: {e}"))?;

    let salt =
        SaltString::encode_b64(&rng_bytes).map_err(|e| anyhow!("Błąd kodowania soli B64: {e}"))?;

    let mut key_bytes = [0u8; KEY_SIZE];
    Argon2::default()
        .hash_password_into(
            password.as_bytes(),
            salt.as_str().as_bytes(),
            &mut key_bytes,
        )
        .map_err(|e| anyhow!("Błąd derywacji klucza Argon2id: {e}"))?;

    Ok((SecretKey::from_bytes(key_bytes), salt.to_string()))
}

/// Odtwarza klucz symetryczny z hasła na podstawie istniejącej soli z kontenera
//#region derive_key_with_salt
pub fn derive_key_with_salt(password: &str, salt_str: &str) -> Result<SecretKey> {
    let mut key_bytes = [0u8; KEY_SIZE];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt_str.as_bytes(), &mut key_bytes)
        .map_err(|e| anyhow!("Błąd derywacji klucza z solą: {e}"))?;

    Ok(SecretKey::from_bytes(key_bytes))
}

/// Szyfruje dowolne bajty za pomocą klucza derywowanego z hasła (Argon2id -> AES-GCM)
//#region encrypt_bytes_with_password
pub fn encrypt_bytes_with_password(password: &str, data: &[u8]) -> Result<EncryptedContainer> {
    let (key, salt) = derive_key_from_password(password)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())?;

    let mut nonce_bytes = [0u8; 12];
    getrandom(&mut nonce_bytes).map_err(|e| anyhow!(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| anyhow!(e.to_string()))?;

    Ok(EncryptedContainer {
        salt,
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

/// Odszyfrowuje dowolne bajty za pomocą klucza derywowanego z hasła i soli z kontenera
//#region decrypt_bytes_with_password
pub fn decrypt_bytes_with_password(
    password: &str,
    container: &EncryptedContainer,
) -> Result<Vec<u8>> {
    let key = derive_key_with_salt(password, &container.salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|e| anyhow!(e.to_string()))?;

    let nonce_bytes = hex::decode(&container.nonce).map_err(|e| anyhow!(e.to_string()))?;
    let ciphertext_bytes =
        hex::decode(&container.ciphertext).map_err(|e| anyhow!(e.to_string()))?;
    if nonce_bytes.len() != 12 {
        return Err(anyhow!("Invalid nonce length: expected 12 bytes"));
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let decrypted_bytes = cipher
        .decrypt(nonce, ciphertext_bytes.as_slice())
        .map_err(|e| anyhow!(e.to_string()))?;

    Ok(decrypted_bytes)
}

//#region encrypt_storage_key
pub fn encrypt_storage_key(
    master_key: &SecretKey,
    storage_key: &SecretKey,
) -> Result<EncryptedContainer> {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let salt_str = salt.to_string();

    let cipher = Aes256Gcm::new_from_slice(master_key.as_bytes())?;

    let mut nonce_bytes = [0u8; 12];
    getrandom(&mut nonce_bytes).map_err(|e| anyhow!(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, storage_key.as_bytes().as_slice())
        .map_err(|e| anyhow!(e.to_string()))?;

    Ok(EncryptedContainer {
        salt: salt_str,
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

//#region decrypt_storage_key
pub fn decrypt_storage_key(
    master_key: &SecretKey,
    container: &EncryptedContainer,
) -> Result<SecretKey> {
    let cipher =
        Aes256Gcm::new_from_slice(master_key.as_bytes()).map_err(|e| anyhow!(e.to_string()))?;

    let nonce_bytes = hex::decode(&container.nonce).map_err(|e| anyhow!(e.to_string()))?;
    let ciphertext_bytes =
        hex::decode(&container.ciphertext).map_err(|e| anyhow!(e.to_string()))?;
    if nonce_bytes.len() != 12 {
        return Err(anyhow!("Invalid nonce length: expected 12 bytes"));
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut decrypted_bytes = cipher
        .decrypt(nonce, ciphertext_bytes.as_slice())
        .map_err(|e| anyhow!(e.to_string()))?;

    if decrypted_bytes.len() != KEY_SIZE {
        decrypted_bytes.zeroize();
        return Err(anyhow!("Invalid key length recovered"));
    }

    let mut out = [0u8; KEY_SIZE];
    out.copy_from_slice(&decrypted_bytes);
    decrypted_bytes.zeroize();

    Ok(SecretKey::from_bytes(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_invalid_nonce_len_returns_err() {
        let (_k, salt) = derive_key_from_password("test-password").expect("derive failed");

        let container = EncryptedContainer {
            salt,
            // intentionally wrong nonce length (8 bytes instead of 12)
            nonce: hex::encode(vec![0u8; 8]),
            ciphertext: hex::encode(vec![]),
        };

        let res = decrypt_bytes_with_password("test-password", &container);
        assert!(res.is_err(), "Expected error for invalid nonce length");
    }
}
