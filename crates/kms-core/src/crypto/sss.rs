use crate::crypto::keys::{KEY_SIZE, SecretKey};
use anyhow::{Result, bail};
use ssss::{SsssConfig, gen_shares, unlock};

pub fn split_shares(secret: &SecretKey, shares: u8, threshold: u8) -> Result<Vec<(u8, String)>> {
    if shares == 0 {
        bail!("Total shares must be greater than zero");
    }
    if threshold == 0 {
        bail!("Threshold must be greater than zero");
    }
    if threshold > shares {
        bail!("Threshold cannot be greater than total shares");
    }
    if threshold < 2 {
        bail!("Threshold must be at least 2");
    }

    let config = SsssConfig::builder()
        .num_shares(shares)
        .threshold(threshold)
        .build();

    let share_strings = gen_shares(&config, secret.as_bytes().as_slice())?;
    let mut result = Vec::with_capacity(share_strings.len());
    for (index, share) in share_strings.into_iter().enumerate() {
        result.push(((index as u8) + 1, share));
    }

    Ok(result)
}

pub fn combine_shares(shares: &[(u8, String)]) -> Result<SecretKey> {
    if shares.is_empty() {
        bail!("At least one share is required to reconstruct the key");
    }

    let share_strings: Vec<String> = shares.iter().map(|(_, value)| value.clone()).collect();
    let recovered_bytes = unlock(&share_strings)?;

    if recovered_bytes.len() != KEY_SIZE {
        bail!("Reconstructed key has invalid size");
    }

    let mut key_arr = [0u8; KEY_SIZE];
    key_arr.copy_from_slice(&recovered_bytes);

    Ok(SecretKey::from_bytes(key_arr))
}
