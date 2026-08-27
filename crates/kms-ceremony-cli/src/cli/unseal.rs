use anyhow::{Context, Result, bail};
use dialoguer::{Input, Password};
use std::collections::HashSet;
use std::io::{IsTerminal, stdin};
use std::path::PathBuf;
use tokio::io::AsyncReadExt;

use kms_core::crypto::aes::decrypt_bytes_with_password;
use kms_core::hsm::client::send_hsm_request;
use kms_core::hsm::protocol::{HsmRequest, HsmResponse};

use crate::storage::files::load_share_directory;

pub async fn handle_unseal_hsm(
    socket_path: String,
    threshold: u8,
    shares_dir: Option<PathBuf>,
) -> Result<()> {
    // Jeśli nie mamy TTY, pozwól na tryb nieinteraktywny (env var lub pipe)

    let mut shares_to_send: Vec<(u8, String)> = Vec::new();

    if let Some(dir) = shares_dir {
        println!("[INFO] Wczytywanie udziałów z katalogu: {}", dir.display());
        let mut records = load_share_directory(&dir).await?;

        if records.len() < threshold as usize {
            bail!(
                "Znaleziono za mało plików udziałów: {} (wymagane: {})",
                records.len(),
                threshold
            );
        }

        // Sortowanie udziałów po indeksie Oficera
        records.sort_by_key(|r| r.index);

        println!("\n[UNSEAL] Wymagana autoryzacja {} Oficerów.", threshold);

        for record in records.into_iter().take(threshold as usize) {
            // Pętla wymuszająca podanie niepustego hasła dla każdego Oficera
            let password = loop {
                let pass = Password::new()
                    .with_prompt(format!("Podaj PIN/hasło dla Oficera nr {}", record.index))
                    .allow_empty_password(false)
                    .interact()
                    .context("Błąd odczytu z terminala")?;

                if !pass.trim().is_empty() {
                    break pass;
                }
                println!("Hasło nie może być puste! Spróbuj ponownie.");
            };

            // BEZPOŚREDNIE UŻYCIE record.container
            let plaintext = decrypt_bytes_with_password(&password, &record.container)
                .with_context(|| format!("Niepoprawne hasło dla Oficera nr {}!", record.index))?;

            // Przekształcenie odtworzonych bajtów udziału do formatu tekstowego
            let share_str = match String::from_utf8(plaintext.clone()) {
                Ok(s) => s,
                Err(_) => hex::encode(&plaintext),
            };

            shares_to_send.push((record.index, share_str));
            println!("[OK] Odszyfrowano udział Oficera nr {}", record.index);
        }
    } else {
        // Non-interactive: attempt to read shares from env var or stdin pipe
        if !stdin().is_terminal() {
            if let Ok(env_shares) = std::env::var("UNSEAL_SHARES") {
                // Expected format: lines "index:share_hex" separated by newlines
                for line in env_shares.lines() {
                    let ln = line.trim();
                    if ln.is_empty() {
                        continue;
                    }
                    if let Some(pos) = ln.find(':') {
                        let idx = ln[..pos]
                            .trim()
                            .parse::<u8>()
                            .context("Invalid share index in UNSEAL_SHARES")?;
                        let share = ln[pos + 1..].trim().to_string();
                        shares_to_send.push((idx, share));
                    } else {
                        bail!("UNSEAL_SHARES has invalid format; expected lines 'index:share'")
                    }
                }
            } else {
                // Read from stdin pipe
                let mut stdin_buf = String::new();
                tokio::io::stdin().read_to_string(&mut stdin_buf).await?;
                for line in stdin_buf.lines() {
                    let ln = line.trim();
                    if ln.is_empty() {
                        continue;
                    }
                    if let Some(pos) = ln.find(':') {
                        let idx = ln[..pos]
                            .trim()
                            .parse::<u8>()
                            .context("Invalid share index from stdin")?;
                        let share = ln[pos + 1..].trim().to_string();
                        shares_to_send.push((idx, share));
                    } else {
                        bail!("Stdin input has invalid format; expected lines 'index:share'");
                    }
                }
            }
        } else {
            println!("[INFO] Tryb interaktywnego wprowadzania udziałów.");
            for i in 1..=threshold {
                let index: u8 = Input::new()
                    .with_prompt(format!("Podaj numer Oficera ({i}/{threshold})"))
                    .interact()?;

                let share_hex: String = Password::new()
                    .with_prompt(format!("Wklej treść udziału dla Oficera nr {index}"))
                    .interact()?;

                shares_to_send.push((index, share_hex.trim().to_string()));
            }
        }
    }

    send_init_master_key_request(socket_path, threshold, shares_to_send).await
}

async fn send_init_master_key_request(
    socket_path: String,
    threshold: u8,
    shares: Vec<(u8, String)>,
) -> Result<()> {
    let mut seen_indices = HashSet::with_capacity(shares.len());
    for (index, _) in &shares {
        if !seen_indices.insert(index) {
            bail!(
                "Wykryto powielony indeks Oficera ({index})! Każdy udział musi pochodzić od innego Oficera."
            );
        }
    }

    let request = HsmRequest::InitMasterKey { threshold, shares };

    match send_hsm_request(&socket_path, &request, None).await {
        Ok(HsmResponse::MasterKeyInitialized) => {
            println!("✅ Master Key został pomyślnie odtworzony w vHSM! Daemon jest gotowy.");
            Ok(())
        }
        Ok(HsmResponse::Error { code, message }) => {
            bail!("Błąd odblokowania vHSM [{code}]: {message}")
        }
        Ok(_) => bail!("Nieoczekiwana odpowiedź z vHSM"),
        Err(err) => bail!("Błąd komunikacji z vHSM: {err}"),
    }
}
