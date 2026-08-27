use anyhow::{Context, Result, bail};
use zeroize::{Zeroize, Zeroizing};

use kms_core::hsm::client::send_hsm_request;
use kms_core::hsm::protocol::{HsmRequest, HsmResponse};

pub async fn handle_encrypt(socket_path: String, plaintext: String) -> Result<()> {
    let request = HsmRequest::Encrypt {
        key_id: "master_key".to_string(),
        key_version: None,
        plaintext: plaintext.into_bytes(),
    };

    match send_hsm_request(&socket_path, &request, None).await {
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

    match send_hsm_request(&socket_path, &request, None).await {
        Ok(HsmResponse::Decrypted {
            plaintext,
            key_version: _,
        }) => match String::from_utf8(plaintext) {
            Ok(s) => {
                let decrypted_str = Zeroizing::new(s);
                println!("Plaintext: {}", *decrypted_str);
                Ok(())
            }
            Err(e) => {
                let mut bytes = e.into_bytes();
                bytes.zeroize();
                bail!("Tekst odszyfrowany nie jest prawidłowym UTF-8")
            }
        },
        Ok(HsmResponse::Error { code, message }) => {
            bail!("Błąd dekodowania [{code}]: {message}")
        }
        Ok(_) => bail!("Otrzymano nieoczekiwaną odpowiedź z HSM"),
        Err(err) => bail!("Błąd komunikacji z HSM: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroize;

    #[test]
    fn utf8_decode_failure_zeroizes_plaintext() {
        // simulate invalid UTF-8 bytes coming from HSM
        let invalid: Vec<u8> = vec![0xff, 0xff, 0xff];

        match String::from_utf8(invalid) {
            Ok(_) => panic!("shouldn't decode"),
            Err(e) => {
                let mut bytes = e.into_bytes();
                bytes.zeroize();
                assert!(bytes.iter().all(|b| *b == 0));
            }
        }
    }
}
