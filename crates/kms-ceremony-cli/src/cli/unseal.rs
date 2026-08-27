use anyhow::{Context, Result, bail};
use dialoguer::Password;
use std::collections::HashSet;
use std::io::{IsTerminal, stdin};
use std::path::PathBuf;
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

use kms_core::crypto::aes::decrypt_bytes_with_password;
use kms_core::hsm::client::send_hsm_request;
use kms_core::hsm::protocol::{HsmRequest, HsmResponse};

use crate::storage::files::{ShareFileRecord, load_share_directory};

pub async fn handle_unseal_hsm(
    socket_path: String,
    threshold: u8,
    shares_dir: PathBuf,
    share_files: Vec<PathBuf>,
) -> Result<()> {
    // Jeśli nie mamy TTY, pozwól na tryb nieinteraktywny (env var lub pipe)

    let mut shares_to_send: Vec<(u8, String)> = Vec::new();

    if stdin().is_terminal() {
        // Interactive TTY mode: load ShareFileRecord from provided files or from shares_dir
        let mut records: Vec<ShareFileRecord> = Vec::new();

        if !share_files.is_empty() {
            println!("[INFO] Wczytywanie udziałów z podanych plików...");
            for p in share_files.iter() {
                let p = p.clone();
                if !p.is_file() {
                    println!("[WARN] Pomijam nieistniejący plik: {}", p.display());
                    continue;
                }
                let content = tokio::fs::read_to_string(&p)
                    .await
                    .with_context(|| format!("Nie można odczytać pliku: {}", p.display()))?;
                let record: ShareFileRecord = serde_json::from_str(&content)
                    .with_context(|| format!("Niepoprawny JSON w pliku: {}", p.display()))?;
                records.push(record);
            }
        } else {
            println!(
                "[INFO] Wczytywanie udziałów z katalogu: {}",
                shares_dir.display()
            );
            records = load_share_directory(&shares_dir).await?;
        }

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

        const MAX_ATTEMPTS: u8 = 3;
        for record in records.into_iter() {
            if shares_to_send.len() >= threshold as usize {
                break;
            }

            let mut success = false;
            for attempt in 1..=MAX_ATTEMPTS {
                let password = Password::new()
                    .with_prompt(format!(
                        "Podaj PIN/hasło dla Oficera nr {} (próba {}/{})",
                        record.index, attempt, MAX_ATTEMPTS
                    ))
                    .allow_empty_password(false)
                    .interact()
                    .context("Błąd odczytu z terminala")?;

                if password.trim().is_empty() {
                    println!("Hasło nie może być puste!");
                    continue;
                }

                match decrypt_bytes_with_password(&password, &record.container) {
                    Ok(decrypted) => {
                        let plaintext_z = Zeroizing::new(decrypted);
                        let share_str = match String::from_utf8(plaintext_z.to_vec()) {
                            Ok(s) => s,
                            Err(_) => hex::encode(&*plaintext_z),
                        };
                        shares_to_send.push((record.index, share_str));
                        println!("[OK] Odszyfrowano udział Oficera nr {}", record.index);
                        success = true;
                        break;
                    }
                    Err(_) => {
                        if attempt < MAX_ATTEMPTS {
                            println!(
                                "Niepoprawne hasło dla Oficera nr {}. Spróbuj ponownie.",
                                record.index
                            );
                        } else {
                            println!(
                                "Niepoprawne hasło dla Oficera nr {}. Pomijam ten plik po {} próbach.",
                                record.index, MAX_ATTEMPTS
                            );
                        }
                    }
                }
            }

            if !success {
                // continue to next record; we'll check later if we have enough shares
                continue;
            }
        }

        if shares_to_send.len() < threshold as usize {
            bail!(
                "Nie udało się odszyfrować wystarczającej liczby udziałów (wymagane: {}).",
                threshold
            );
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
