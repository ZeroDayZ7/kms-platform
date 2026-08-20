use anyhow::{Context, Result, bail};
use dialoguer::Password;
use std::fs;
use std::path::PathBuf;

use kms_core::crypto::aes::encrypt_with_password;
use kms_core::crypto::keys::SecretKey;
use kms_core::hsm::client::send_hsm_request;
use kms_core::hsm::protocol::{HsmRequest, HsmResponse};

use crate::storage::files::write_share_file;

pub async fn handle_interactive_ceremony(
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

    println!("[INFO] Łączenie z vHSM ({socket_path}) w celu wygenerowania Master Key...");

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

        let raw_share_bytes = hex::decode(&hex_val)?;
        let share_secret = SecretKey::from_bytes(raw_share_bytes.try_into().unwrap());

        // Bezpieczne derywowanie klucza z Argon2 + losowa sól + AES-GCM
        let encrypted_container = encrypt_with_password(&password, &share_secret)?;
        let encrypted_json = serde_json::to_string(&encrypted_container)?;

        let file_path =
            write_share_file(&share_dir, index, threshold, shares_count, encrypted_json)?;
        println!(
            "[OK] Udział nr {index} został zaszyfrowany i zapisany w {}",
            file_path.display()
        );
    }

    println!("\n[SUCCESS] Ceremonia zakończona! vHSM jest gotowy do pracy.");
    Ok(())
}
