use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use kms_core::hsm::client::send_hsm_request;
use kms_core::hsm::protocol::{HsmRequest, HsmResponse};

pub async fn handle_encrypt(socket_path: String, plaintext: String) -> Result<()> {
    let request = HsmRequest::Encrypt {
        key_id: "master_key".to_string(),
        key_version: None,
        plaintext: plaintext.into_bytes(),
    };

    match send_hsm_request(&socket_path, &request).await {
        Ok(HsmResponse::Encrypted {
            ciphertext,
            key_version: _,
        }) => {
            println!("Ciphertext (HEX): {}", hex::encode(ciphertext));
            Ok(())
        }
        Ok(HsmResponse::Error { code, message }) => {
            bail!("Błąd szyfrowania [{code}]: {message}")
        }
        Ok(_) => bail!("Otrzymano nieoczekiwaną odpowiedź z HSM"),
        Err(err) => bail!("Błąd komunikacji z HSM: {err}"),
    }
}

pub async fn handle_decrypt(socket_path: String, ciphertext_hex: String) -> Result<()> {
    let ciphertext = hex::decode(ciphertext_hex.trim()).context("Nieprawidłowy HEX szyfrogramu")?;
    let request = HsmRequest::Decrypt {
        key_id: "master_key".to_string(),
        key_version: None,
        ciphertext,
    };

    match send_hsm_request(&socket_path, &request).await {
        Ok(HsmResponse::Decrypted {
            plaintext,
            key_version: _,
        }) => {
            let decrypted_str = Zeroizing::new(
                String::from_utf8(plaintext)
                    .context("Tekst odszyfrowany nie jest prawidłowym UTF-8")?,
            );
            println!("Plaintext: {}", *decrypted_str);
            Ok(())
        }
        Ok(HsmResponse::Error { code, message }) => {
            bail!("Błąd dekodowania [{code}]: {message}")
        }
        Ok(_) => bail!("Otrzymano nieoczekiwaną odpowiedź z HSM"),
        Err(err) => bail!("Błąd komunikacji z HSM: {err}"),
    }
}
