use crate::crypto::keys::{KEY_SIZE, SecretKey};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version, password_hash::SaltString};
use getrandom::getrandom;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedContainer {
    pub salt: String,       // Sól dla Argon2
    pub nonce: String,      // IV dla AES-GCM
    pub ciphertext: String, // Zaszyfrowane dane
}

// Parametry derywacji klucza Argon2id zgodne z zaleceniami OWASP / RFC 9106 dla środowisk o wysokim rygorze bezpieczeństwa:
// - m_cost (Memory cost): Zużycie pamięci RAM w KiB. Utrudnia masowe ataki kryptoanalityczne przy użyciu dedykowanych układów GPU/ASIC/FPGA. Dobre wartości: 19456 KiB (19 MiB) do 65536 KiB (64 MiB).
pub const ARGON2_M_COST: u32 = 65536;

// - t_cost (Time cost): Liczba iteracji określająca czas wykonywania algorytmu. Dobre wartości: 1 do 3 iteracji (wyższy rygor w systemach KMS).
pub const ARGON2_T_COST: u32 = 3;

// - p_cost (Parallelism cost): Liczba wątków przetwarzających dane równolegle. Dobre wartości: 1 do 4 wątków (w zależności od architektury CPU).
pub const ARGON2_P_COST: u32 = 4;

fn get_argon2_instance() -> Result<Argon2<'static>> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_SIZE))
        .map_err(|e| anyhow!("Błąd konfiguracji parametrów Argon2id: {e}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Generuje losową sól i derywuje klucz symetryczny AES-256 z podanego hasła (Argon2id)
//#region derive_key_from_password
pub fn derive_key_from_password(password: &str) -> Result<(SecretKey, String)> {
    let mut rng_bytes = [0u8; 16];
    getrandom(&mut rng_bytes).map_err(|e| anyhow!("Nie udało się wygenerować soli: {e}"))?;

    let salt =
        SaltString::encode_b64(&rng_bytes).map_err(|e| anyhow!("Błąd kodowania soli B64: {e}"))?;

    let mut key_bytes = [0u8; KEY_SIZE];
    get_argon2_instance()?
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
    get_argon2_instance()?
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

    // Wrap ciphertext in Zeroizing so its contents are zeroed when dropped
    let ciphertext_z = Zeroizing::new(ciphertext);
    let ciphertext_hex = hex::encode(&*ciphertext_z);

    // Nonce is not secret but zeroize the stack buffer anyway
    let nonce_hex = hex::encode(nonce_bytes);
    nonce_bytes.zeroize();

    Ok(EncryptedContainer {
        salt,
        nonce: nonce_hex,
        ciphertext: ciphertext_hex,
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

    // Wrap ciphertext_bytes in Zeroizing so it is zeroed after decrypt
    let ciphertext_z = Zeroizing::new(ciphertext_bytes);
    let decrypted_bytes = cipher
        .decrypt(nonce, &ciphertext_z[..])
        .map_err(|e| anyhow!(e.to_string()))?;

    // zeroize nonce buffer
    // nonce_bytes is owned Vec<u8>
    let mut nb = nonce_bytes;
    nb.zeroize();

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
