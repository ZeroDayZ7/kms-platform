use anyhow::{Context, Result, anyhow, bail};
use dialoguer::Password;
use std::fs;
use std::path::PathBuf;

use kms_core::crypto::aes::encrypt_bytes_with_password;
use kms_core::crypto::keys::{KEY_SIZE, SecretKey};
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

        // 1. Usunięcie prefiksu typu "1-", jeśli występuje w ciągu udziału
        let clean_hex = if let Some((_, data)) = hex_val.split_once('-') {
            data
        } else {
            &hex_val
        };

        // 2. Normalizacja – obsługa nieparzystej długości HEX zgodnie z wymogami Clippy
        let formatted_hex = if !clean_hex.len().is_multiple_of(2) {
            format!("0{clean_hex}")
        } else {
            clean_hex.to_string()
        };

        // 3. Dekodowanie z formatu HEX na bajty
        let raw_share_bytes = hex::decode(&formatted_hex)
            .with_context(|| format!("Nieprawidłowy format HEX udziału nr {index}"))?;

        // 4. Bezpieczna konwersja na bajty klucza bez .unwrap()
        let share_bytes_arr: [u8; KEY_SIZE] = raw_share_bytes.try_into().map_err(|_| {
            anyhow!("Nieprawidłowa długość bajtów udziału nr {index} (oczekiwano {KEY_SIZE} B)")
        })?;

        let share_secret = SecretKey::from_bytes(share_bytes_arr);

        // 5. Szyfrowanie kluczem wygenerowanym z hasła
        let encrypted_container = encrypt_bytes_with_password(&password, share_secret.as_bytes())?;

        // 6. Zapis kontenera do pliku
        let file_path = write_share_file(
            &share_dir,
            index,
            threshold,
            shares_count,
            encrypted_container,
        )?;

        println!(
            "[OK] Udział nr {index} został zaszyfrowany i zapisany w {}",
            file_path.display()
        );
    }

    println!("\n[SUCCESS] Ceremonia zakończona! vHSM jest gotowy do pracy.");
    Ok(())
}
