// crates/kms-core/src/crypto/sss.rs
use crate::crypto::keys::{KEY_SIZE, SecretKey};
use anyhow::{Context, Result, bail};
use ssss::{SsssConfig, gen_shares, unlock};

pub type KmsError = anyhow::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretShare {
    pub index: u8,
    pub value: String,
}

pub fn split_secret(
    secret: &[u8],
    threshold: u8,
    shares_count: u8,
) -> Result<Vec<SecretShare>, KmsError> {
    if secret.len() != KEY_SIZE {
        bail!("Secret length must be exactly {KEY_SIZE} bytes");
    }
    if shares_count == 0 {
        bail!("Total shares must be greater than zero");
    }
    if threshold == 0 {
        bail!("Threshold must be greater than zero");
    }
    if threshold > shares_count {
        bail!("Threshold cannot be greater than total shares");
    }
    if threshold < 2 {
        bail!("Threshold must be at least 2");
    }

    let config = SsssConfig::builder()
        .num_shares(shares_count)
        .threshold(threshold)
        .build();

    let share_strings = gen_shares(&config, secret)?;

    let shares = share_strings
        .into_iter()
        .enumerate()
        .map(|(index, value)| SecretShare {
            index: (index as u8) + 1,
            value,
        })
        .collect();

    Ok(shares)
}

pub fn combine_shares(shares: &[SecretShare]) -> Result<Vec<u8>, KmsError> {
    if shares.is_empty() {
        bail!("At least one share is required to reconstruct the key");
    }

    let share_strings: Vec<String> = shares.iter().map(|share| share.value.clone()).collect();
    let recovered_bytes = unlock(&share_strings).with_context(|| {
        format!(
            "Failed to reconstruct secret from {} shares",
            share_strings.len()
        )
    })?;

    if recovered_bytes.len() != KEY_SIZE {
        bail!("Reconstructed key has invalid size");
    }

    Ok(recovered_bytes)
}

pub fn split_shares(secret: &SecretKey, shares: u8, threshold: u8) -> Result<Vec<(u8, String)>> {
    let secret_bytes = secret.as_bytes().to_vec();
    let shared = split_secret(&secret_bytes, threshold, shares)?;
    Ok(shared
        .into_iter()
        .map(|share| {
            // Dopisywanie wiodącego zera dla nieparzystej długości
            let formatted_value = if share.value.len() % 2 != 0 {
                format!("0{}", share.value)
            } else {
                share.value
            };
            (share.index, formatted_value)
        })
        .collect())
}

pub fn combine_shares_legacy(shares: &[(u8, String)]) -> Result<SecretKey> {
    let secret_shares: Vec<SecretShare> = shares
        .iter()
        .map(|(index, value)| {
            let formatted_value = if value.len() % 2 != 0 {
                format!("0{value}")
            } else {
                value.clone()
            };
            SecretShare {
                index: *index,
                value: formatted_value,
            }
        })
        .collect();

    let recovered_bytes = combine_shares(&secret_shares)?;
    let mut key_arr = [0u8; KEY_SIZE];
    key_arr.copy_from_slice(&recovered_bytes);

    Ok(SecretKey::from_bytes(key_arr))
}
