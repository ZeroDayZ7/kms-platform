mod cli;
mod crypto;
mod storage;

use anyhow::{Context, Result, bail};
use clap::Parser;
use dialoguer::{Input, Password};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

use kms_core::hsm::client::send_hsm_request;
use kms_core::hsm::protocol::{HsmRequest, HsmResponse};

use crate::cli::args::{CliArgs, Commands};
use crate::storage::files::{load_share_directory, write_share_file};

/// 1. Interaktywna ceremonia inicjalizacji Master Key wewnątrz vHSM
async fn handle_interactive_ceremony(
    socket_path: String,
    shares_count: u8,
    threshold: u8,
    output_dir: PathBuf,
) -> Result<()> {
    if shares_count == 0 || threshold == 0 {
        bail!("Liczba udziałów i próg muszą być większe od zera.");
    }
    if threshold > shares_count {
        bail!("Próg nie może być większy niż całkowita liczba udziałów.");
    }

    println!(
        "[INFO] Łączenie z vHSM ({}) w celu wygenerowania Master Key...",
        socket_path
    );

    let request = HsmRequest::GenerateCeremony {
        threshold,
        total_shares: shares_count,
    };

    let response = send_hsm_request(&socket_path, &request)
        .await
        .context("Nie udało się połączyć z daemonem vHSM")?;

    let raw_shares = match response {
        HsmResponse::CeremonyGenerated { shares } => shares,
        HsmResponse::Error { code, message } => bail!("Błąd HSM [{code}]: {message}"),
        _ => bail!("Otrzymano nieoczekiwaną odpowiedź z vHSM"),
    };

    fs::create_dir_all(&output_dir)?;
    let share_dir = output_dir.join("shares");
    fs::create_dir_all(&share_dir)?;

    println!("\n[CEREMONY] vHSM wygenerował Master Key w pamięci RAM!");
    println!(
        "[CEREMONY] Rozpoczynamy zabezpieczanie {} udziałów dla Oficerów Bezpieczeństwa.\n",
        raw_shares.len()
    );

    for (index, hex_val) in raw_shares {
        println!("--------------------------------------------------");
        println!("Oficerzie nr {index}, podejmij swój udział.");

        let password = Password::new()
            .with_prompt(format!(
                "Podaj hasło/PIN do zaszyfrowania Udziału nr {index}"
            ))
            .interact()?;

        let confirm = Password::new().with_prompt("Potwierdź hasło").interact()?;

        if password != confirm {
            bail!("Hasła się nie zgadzają! Przerwano ceremonię.");
        }

        let file_path = write_share_file(&share_dir, index, threshold, shares_count, hex_val)?;
        println!(
            "[OK] Udział nr {index} został pomyślnie zapisany w {}",
            file_path.display()
        );
    }

    println!("\n[SUCCESS] Ceremonia zakończona! vHSM jest gotowy do pracy.");
    Ok(())
}

/// 2. Odblokowanie (Unseal) HSM poprzez wczytanie udziałów z plików/terminala
async fn handle_unseal_hsm(
    socket_path: String,
    threshold: u8,
    shares_dir: Option<PathBuf>,
) -> Result<()> {
    let mut shares_to_send: Vec<(u8, String)> = Vec::new();

    if let Some(dir) = shares_dir {
        println!("[INFO] Wczytywanie udziałów z katalogu: {}", dir.display());
        let records = load_share_directory(&dir)?;

        if records.len() < threshold as usize {
            bail!(
                "Znaleziono za mało plików udziałów: {} (wymagane: {})",
                records.len(),
                threshold
            );
        }

        for record in records.into_iter().take(threshold as usize) {
            shares_to_send.push((record.index, record.share_hex));
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

    let request = HsmRequest::InitMasterKey {
        threshold,
        shares: shares_to_send,
    };

    match send_hsm_request(&socket_path, &request).await {
        Ok(HsmResponse::MasterKeyInitialized) => {
            println!("✅ Master Key został pomyślnie odtworzony w vHSM! Daemon jest gotowy.")
        }
        Ok(HsmResponse::Error { code, message }) => {
            bail!("Błąd odblokowania vHSM [{code}]: {message}")
        }
        Ok(_) => bail!("Nieoczekiwana odpowiedź z vHSM"),
        Err(err) => bail!("Błąd komunikacji z vHSM: {err}"),
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = CliArgs::parse();

    match cli.command {
        Commands::Interactive {
            socket_path,
            shares,
            threshold,
            output_dir,
        } => {
            handle_interactive_ceremony(socket_path, shares, threshold, output_dir).await?;
        }

        Commands::Unseal {
            socket_path,
            threshold,
            shares_dir,
        } => {
            handle_unseal_hsm(socket_path, threshold, shares_dir).await?;
        }

        Commands::InitMasterKey {
            socket_path,
            threshold,
            shares,
        } => {
            let mut parsed_shares = Vec::new();
            for raw_share in shares {
                if let Some((idx_str, hex_str)) = raw_share.split_once(':') {
                    let idx = idx_str
                        .parse::<u8>()
                        .context("Nieprawidłowy indeks udziału")?;
                    parsed_shares.push((idx, hex_str.trim().to_string()));
                } else {
                    bail!("Udział podany w CLI musi mieć format 'INDEX:HEX' (np. '1:a3f5...')");
                }
            }

            let request = HsmRequest::InitMasterKey {
                threshold,
                shares: parsed_shares,
            };

            match send_hsm_request(&socket_path, &request).await {
                Ok(HsmResponse::MasterKeyInitialized) => {
                    println!("✅ Klucz główny vHSM został pomyślnie załadowany.")
                }
                Ok(HsmResponse::Error { code, message }) => {
                    bail!("Błąd HSM [{code}]: {message}")
                }
                Ok(_) => bail!("Otrzymano nieoczekiwaną odpowiedź z HSM"),
                Err(err) => bail!("Błąd komunikacji z HSM: {err}"),
            }
        }

        Commands::Encrypt {
            socket_path,
            plaintext,
        } => {
            let request = HsmRequest::Encrypt {
                key_id: "master_key".to_string(),
                key_version: None,
                plaintext: plaintext.into_bytes(),
            };

            match send_hsm_request(&socket_path, &request).await {
                Ok(HsmResponse::Encrypted { ciphertext }) => {
                    println!("Ciphertext (HEX): {}", hex::encode(ciphertext));
                }
                Ok(HsmResponse::Error { code, message }) => {
                    bail!("Błąd szyfrowania [{code}]: {message}")
                }
                Ok(_) => bail!("Otrzymano nieoczekiwaną odpowiedź z HSM"),
                Err(err) => bail!("Błąd komunikacji z HSM: {err}"),
            }
        }

        Commands::Decrypt {
            socket_path,
            ciphertext_hex,
        } => {
            let ciphertext =
                hex::decode(ciphertext_hex.trim()).context("Nieprawidłowy HEX szyfrogramu")?;
            let request = HsmRequest::Decrypt {
                key_id: "master_key".to_string(),
                key_version: None,
                ciphertext,
            };

            match send_hsm_request(&socket_path, &request).await {
                Ok(HsmResponse::Decrypted { plaintext }) => {
                    let decrypted_str = Zeroizing::new(
                        String::from_utf8(plaintext)
                            .context("Tekst odszyfrowany nie jest prawidłowym UTF-8")?,
                    );
                    println!("Plaintext: {}", *decrypted_str);
                }
                Ok(HsmResponse::Error { code, message }) => {
                    bail!("Błąd dekodowania [{code}]: {message}")
                }
                Ok(_) => bail!("Otrzymano nieoczekiwaną odpowiedź z HSM"),
                Err(err) => bail!("Błąd komunikacji z HSM: {err}"),
            }
        }
    }

    Ok(())
}
