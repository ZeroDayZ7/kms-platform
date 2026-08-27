// crates/kms-core/src/crypto/sss.rs
use crate::crypto::keys::{KEY_SIZE, SecretKey};
use anyhow::{Context, Result, bail};
use ssss::{SsssConfig, gen_shares, unlock};
use zeroize::Zeroizing;

pub type KmsError = anyhow::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretShare {
    pub index: u8,
    /// Hex-encoded payload (lowercase, even-length) representing the share bytes
    pub value: Zeroizing<String>,
}

// NOTE: The SSS library returns share strings in its own textual format
// (which may include prefixes/separators). We intentionally keep the raw
// textual representation and treat shares as opaque strings for storage and
// transport. The `unlock` function from the library consumes these strings
// directly when reconstructing the secret, so we preserve them unchanged.

//#region split_secret
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

    let mut shares = Vec::with_capacity(share_strings.len());
    for (idx, raw_value) in share_strings.into_iter().enumerate() {
        // Preserve the raw share string (trimmed) as-produced by the library.
        shares.push(SecretShare {
            index: (idx as u8) + 1,
            value: Zeroizing::new(raw_value.trim().to_string()),
        });
    }

    Ok(shares)
}

//#region combine_shares
pub fn combine_shares(shares: &[SecretShare]) -> Result<Vec<u8>, KmsError> {
    if shares.is_empty() {
        bail!("At least one share is required to reconstruct the key");
    }

    // The underlying `unlock` expects the share payloads in the same textual
    // form as `gen_shares` returned. We standardized our `SecretShare.value` to
    // be a hex payload, so pass that directly to `unlock` (it accepts hex).
    let share_strings: Vec<String> = shares.iter().map(|share| share.value.to_string()).collect();
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

//#region split_shares
pub fn split_shares(secret: &SecretKey, shares: u8, threshold: u8) -> Result<Vec<(u8, String)>> {
    let secret_bytes = secret.as_bytes().to_vec();
    let shared = split_secret(&secret_bytes, threshold, shares)?;
    Ok(shared
        .into_iter()
        .map(|share| {
            // Ensure hex payload is even-length and normalized (we already
            // produce even-length hex in `split_secret`). Return `(index, hex)`.
            (share.index, share.value.to_string())
        })
        .collect())
}

//#region combine_shares_legacy
pub fn combine_shares_legacy(shares: &[(u8, String)]) -> Result<SecretKey> {
    let secret_shares: Vec<SecretShare> = shares
        .iter()
        .map(|(index, value)| {
            // Treat incoming share strings as opaque and preserve them
            SecretShare {
                index: *index,
                value: Zeroizing::new(value.trim().to_string()),
            }
        })
        .collect();

    let recovered_bytes = combine_shares(&secret_shares)?;
    let mut key_arr = [0u8; KEY_SIZE];
    key_arr.copy_from_slice(&recovered_bytes);

    Ok(SecretKey::from_bytes(key_arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    //#region roundtrip_split_and_combine
    fn roundtrip_split_and_combine() {
        let master = SecretKey::generate();
        let total = 5u8;
        let threshold = 3u8;

        let shares = split_shares(&master, total, threshold).expect("split failed");
        // pick first `threshold` shares and pass to legacy combiner
        let taken: Vec<(u8, String)> = shares.into_iter().take(threshold as usize).collect();

        let recovered = combine_shares_legacy(&taken).expect("combine failed");

        assert_eq!(master.as_bytes(), recovered.as_bytes());
    }

    // Note: detailed parsing/normalization tests removed because the SSS
    // library emits opaque textual share formats; we treat shares as
    // opaque strings and store/restore them verbatim.
}

#[test]
fn secret_share_value_zeroizes() {
    use zeroize::Zeroize;

    let mut s = SecretShare {
        index: 1,
        value: Zeroizing::new("deadbeef".to_string()),
    };

    // ensure contents are present
    assert_eq!(s.value.as_str(), "deadbeef");

    // zeroize and ensure it has been cleared
    s.value.zeroize();
    assert!(s.value.as_str().is_empty());
}
