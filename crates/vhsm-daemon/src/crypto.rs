#[cfg(unix)]
use std::collections::HashSet;

#[cfg(unix)]
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};

#[cfg(unix)]
use kms_core::crypto::sss::{combine_shares, split_shares};

#[cfg(unix)]
//#region generate_and_split_master_key
pub fn generate_and_split_master_key(
    total: u8,
    threshold: u8,
) -> Result<(Vec<u8>, Vec<(u8, String)>), String> {
    let master_key = kms_core::crypto::keys::generate_master_key();
    let raw_bytes = master_key.as_bytes().to_vec();

    let shares = split_shares(&master_key, total, threshold)
        .map_err(|e| format!("Failed to split master key: {e}"))?;

    Ok((raw_bytes, shares))
}

#[cfg(unix)]
//#region reconstruct_master_key
pub fn reconstruct_master_key(shares: &[(u8, String)]) -> Result<Vec<u8>, String> {
    if shares.is_empty() {
        return Err("At least one share is required".to_string());
    }

    // Sprawdzenie unikalności indeksów (dedykowana walidacja)
    let mut seen_indices = HashSet::with_capacity(shares.len());
    for (index, _) in shares {
        if !seen_indices.insert(index) {
            return Err(format!("Duplicate share index detected: {index}"));
        }
    }

    let secret_shares = shares
        .iter()
        .map(|(index, value)| kms_core::crypto::sss::SecretShare {
            index: *index,
            value: value.clone(),
        })
        .collect::<Vec<_>>();

    let recovered = combine_shares(&secret_shares)
        .map_err(|err| format!("Failed to reconstruct master key from shares: {err}"))?;

    if recovered.len() != 32 {
        return Err("Recovered master key must be 32 bytes".to_string());
    }

    Ok(recovered)
}

#[cfg(unix)]
//#region encrypt_bytes
pub fn encrypt_bytes(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|err| format!("Failed to initialize AES-GCM: {err}"))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|err| format!("Encryption failed: {err}"))?;

    let mut payload = nonce_bytes.to_vec();
    payload.append(&mut ciphertext);

    Ok(payload)
}

#[cfg(unix)]
//#region decrypt_bytes
pub fn decrypt_bytes(key: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() < 12 {
        return Err("Ciphertext payload too short".to_string());
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|err| format!("Failed to initialize AES-GCM: {err}"))?;

    let (nonce_bytes, raw_ciphertext) = payload.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, raw_ciphertext)
        .map_err(|err| format!("Decryption failed: {err}"))
}
