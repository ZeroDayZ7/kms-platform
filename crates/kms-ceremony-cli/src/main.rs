mod cli;
mod crypto;
mod storage;

use anyhow::{Context, Result, bail};
use clap::Parser;
use dialoguer::Password;
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

use kms_core::hsm::client::send_hsm_request;
use kms_core::hsm::protocol::{HsmRequest, HsmResponse};

use crate::cli::args::{CliArgs, Commands};
use crate::crypto::aes::encrypt_storage_key;
use crate::crypto::keys::generate_master_key;
use crate::crypto::sss::{combine_shares, split_shares};
use crate::storage::files::{
    load_share_directory, write_manifest, write_master_key_file, write_share_file,
};

fn handle_generate(shares: u8, threshold: u8, output_dir: PathBuf) -> Result<()> {
    if shares == 0 || threshold == 0 {
        bail!("Shares and threshold must be greater than zero");
    }
    if threshold > shares {
        bail!("Threshold cannot exceed total shares");
    }
    if threshold < 2 {
        bail!("Threshold must be at least 2 for a KMS ceremony");
    }

    let master_key = generate_master_key();
    let storage_key = generate_master_key();
    let encrypted_storage_key = encrypt_storage_key(&master_key, &storage_key)?;
    let share_items = split_shares(&master_key, shares, threshold)?;

    fs::create_dir_all(&output_dir)?;
    let share_dir = output_dir.join("shares");
    fs::create_dir_all(&share_dir)?;

    let mut share_paths = Vec::new();
    for (index, share_hex) in share_items.iter() {
        let file_path = write_share_file(&share_dir, *index, threshold, shares, share_hex.clone())?;
        share_paths.push(file_path.file_name().unwrap().to_string_lossy().to_string());
    }

    write_manifest(
        &output_dir,
        shares,
        threshold,
        &share_paths,
        encrypted_storage_key.nonce.clone(),
        encrypted_storage_key.ciphertext.clone(),
    )?;

    println!(
        "[OK] Generated master key, storage key, and SSS shares in {}",
        output_dir.display()
    );
    println!("[OK] Share files created in {}", share_dir.display());
    println!(
        "[OK] Ceremony manifest written to {}",
        output_dir.join("ceremony_manifest.json").display()
    );

    Ok(())
}

async fn handle_interactive_ceremony(
    socket_path: String,
    shares_count: u8,
    threshold: u8,
    output_dir: PathBuf,
) -> Result<()> {
    if shares_count == 0 || threshold == 0 {
        bail!("Shares and threshold must be greater than zero");
    }
    if threshold > shares_count {
        bail!("Threshold cannot exceed total shares");
    }

    println!(
        "[INFO] Łączenie z vHSM na {} w celu przeprowadzenia wewnętrznej ceremonii...",
        socket_path
    );

    let request = HsmRequest::GenerateCeremony {
        threshold,
        total_shares: shares_count,
    };

    let response = send_hsm_request(&socket_path, &request)
        .await
        .context("Nie udało się połączyć z vHSM daemonem")?;

    let raw_shares = match response {
        HsmResponse::CeremonyGenerated { shares } => shares,
        HsmResponse::Error { code, message } => bail!("Błąd HSM [{code}]: {message}"),
        _ => bail!("Otrzymano nieoczekiwaną odpowiedź z vHSM"),
    };

    fs::create_dir_all(&output_dir)?;
    let share_dir = output_dir.join("shares");
    fs::create_dir_all(&share_dir)?;

    println!("\n[CEREMONY] vHSM wygenerował klucz główny w bezpiecznej pamięci!");
    println!(
        "[CEREMONY] Teraz nastąpi iteracja po {} oficerach w celu zabezpieczenia udziałów.\n",
        raw_shares.len()
    );

    for (index, hex_val) in raw_shares {
        println!("--------------------------------------------------");
        println!("Oficerie nr {index}, podejdź do terminala.");

        let password = Password::new()
            .with_prompt(format!("Podaj hasło/PIN dla Oficera nr {index}"))
            .interact()?;

        let confirm = Password::new().with_prompt("Potwierdź hasło").interact()?;

        if password != confirm {
            bail!("Hasła się nie zgadzają! Przerwano ceremonię ze względów bezpieczeństwa.");
        }

        let file_path = write_share_file(&share_dir, index, threshold, shares_count, hex_val)?;
        println!(
            "[OK] Udział nr {index} został zaszyfrowany i zapisany w {}",
            file_path.display()
        );
    }

    println!("\n[SUCCESS] Ceremonia zakończona pomyślnie! Master Key w vHSM jest aktywny.");
    Ok(())
}

fn handle_recover(shares_dir: PathBuf, output_key: PathBuf) -> Result<()> {
    if !shares_dir.exists() {
        bail!("Shares directory does not exist: {}", shares_dir.display());
    }

    let share_records = load_share_directory(&shares_dir)?;
    if share_records.is_empty() {
        bail!("No share files found in {}", shares_dir.display());
    }

    let mut sorted = share_records;
    sorted.sort_by_key(|item| item.index);

    let threshold = sorted[0].threshold;
    let total_shares = sorted[0].total_shares;
    if sorted.len() < threshold as usize {
        bail!(
            "Not enough shares to recover the secret: {} available, {} required",
            sorted.len(),
            threshold
        );
    }

    let shares: Vec<(u8, String)> = sorted
        .iter()
        .map(|record| (record.index, record.share_hex.clone()))
        .collect();

    let secret_shares: Vec<kms_core::crypto::sss::SecretShare> = shares
        .iter()
        .map(|(index, value)| kms_core::crypto::sss::SecretShare {
            index: *index,
            value: value.clone(),
        })
        .collect();

    let recovered_bytes = combine_shares(&secret_shares)?;
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&recovered_bytes);
    let recovered_key = crate::crypto::keys::SecretKey::from_bytes(key_bytes);
    write_master_key_file(&output_key, &recovered_key)?;

    println!("[OK] Reconstructed master key from {} shares", sorted.len());
    println!("[OK] Saved recovered key to {}", output_key.display());
    println!("[INFO] Threshold: {threshold}, total shares: {total_shares}");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = CliArgs::parse();

    match cli.command {
        Commands::Generate {
            shares,
            threshold,
            output_dir,
        } => {
            handle_generate(shares, threshold, output_dir)?;
        }
        Commands::Recover {
            shares_dir,
            output_key,
        } => {
            handle_recover(shares_dir, output_key)?;
        }
        Commands::Interactive {
            socket_path,
            shares,
            threshold,
            output_dir,
        } => {
            handle_interactive_ceremony(socket_path, shares, threshold, output_dir).await?;
        }
        Commands::InitMasterKey {
            socket_path,
            threshold,
            shares,
        } => {
            let cleaned_shares: Vec<(u8, String)> = shares
                .into_iter()
                .enumerate()
                .map(|(index, share)| {
                    let index = (index + 1) as u8;
                    (index, share.trim().to_string())
                })
                .collect();

            let request = HsmRequest::InitMasterKey {
                threshold,
                shares: cleaned_shares,
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
