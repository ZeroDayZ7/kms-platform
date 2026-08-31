// crates/kms-ceremony-cli/src/cli/ceremony.rs
use anyhow::{Context, Result, bail};
use dialoguer::Password;
use std::path::PathBuf;
use tokio::fs;
use zeroize::Zeroizing;

use kms_core::crypto::aes::encrypt_bytes_with_password;
use kms_core::hsm::client::send_hsm_request;
use kms_core::hsm::protocol::{HsmRequest, HsmResponse};

use crate::storage::files::write_share_file;

pub async fn handle_interactive_ceremony(
    socket_path: String,
    shares_count: u8,
    threshold: u8,
    output_dir: PathBuf,
    admin_cn: String,
    server_domain: String,
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

    let response = send_hsm_request(&socket_path, &request, None)
        .await
        .context("Nie udało się połączyć z daemonem vHSM")?;

    let raw_shares = match response {
        HsmResponse::CeremonyGenerated { shares } => shares,
        HsmResponse::Error { code, message } => bail!("Błąd HSM [{code}]: {message}"),
        _ => bail!("Otrzymano nieoczekiwaną odpowiedź z vHSM"),
    };

    fs::create_dir_all(&output_dir).await?;
    let share_dir = output_dir.join("shares");
    fs::create_dir_all(&share_dir).await?;

    println!("\n[CEREMONY] vHSM wygenerował Master Key w pamięci RAM!");
    println!(
        "[CEREMONY] Rozpoczynamy zabezpieczanie {} udziałów dla Oficerów Bezpieczeństwa.\n",
        raw_shares.len()
    );

    for (index, raw_share_str) in raw_shares {
        println!("--------------------------------------------------");
        println!("Oficerzie nr {index}, podejmij swój udział.");

        let password = Zeroizing::new(
            Password::new()
                .with_prompt(format!(
                    "Podaj hasło/PIN do zaszyfrowania Udziału nr {index}"
                ))
                .interact()?,
        );

        let confirm = Zeroizing::new(Password::new().with_prompt("Potwierdź hasło").interact()?);

        if password != confirm {
            bail!("Hasła się nie zgadzają! Przerwano ceremonię.");
        }

        // Pobieramy surowe bajty z wartości SSS zwrócenie z vHSM (bez dekodowania z HEX)
        let raw_share_str = Zeroizing::new(raw_share_str);
        let share_bytes = raw_share_str.as_bytes();

        // Szyfrowanie udziału SSS hasłem Oficera
        let encrypted_container = encrypt_bytes_with_password(&password, share_bytes)?;

        // Zapis kontenera do pliku
        let file_path = write_share_file(
            &share_dir,
            index,
            threshold,
            shares_count,
            encrypted_container,
        )
        .await?;

        println!(
            "[OK] Udział nr {index} został zaszyfrowany i zapisany w {}",
            file_path.display()
        );
    }

    println!("\n[SUCCESS] Ceremonia zakończona! vHSM jest gotowy do pracy.");

    // Bootstrap PKI: ask vHSM to generate CA and issue server/admin certs
    println!("[PKI] Requesting PKI bootstrap from vHSM...");
    let req = HsmRequest::BootstrapPki {
        admin_cn: admin_cn.clone(),
        server_domain: server_domain.clone(),
    };
    let resp = send_hsm_request(&socket_path, &req, None)
        .await
        .context("Failed to request BootstrapPki from vHSM")?;

    match resp {
        HsmResponse::BootstrapPkiResult {
            ca_pem,
            server_cert_pem,
            server_key_pem,
            admin_cert_pem,
            admin_key_pem,
        } => {
            let pki_dir = output_dir.join("pki");
            fs::create_dir_all(&pki_dir).await?;

            let ca_path = pki_dir.join("ca.crt");
            let admin_crt_path = pki_dir.join("admin.crt");
            let admin_key_path = pki_dir.join("admin.key");
            let server_crt_path = pki_dir.join("server.crt");
            let server_key_path = pki_dir.join("server.key");

            fs::write(&ca_path, ca_pem.clone()).await?;
            fs::write(&admin_crt_path, admin_cert_pem.clone()).await?;
            fs::write(&admin_key_path, admin_key_pem.clone()).await?;
            fs::write(&server_crt_path, server_cert_pem.clone()).await?;
            fs::write(&server_key_path, server_key_pem.clone()).await?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&admin_key_path).await?.permissions();
                perms.set_mode(0o600);
                fs::set_permissions(&admin_key_path, perms).await?;
            }

            println!(
                "[PKI] Bootstrap PKI artifacts written to {}",
                pki_dir.display()
            );

            // Optionally register admin cert in kms-service if KMS_SERVICE_URL env provided
            if let Ok(service_url) = std::env::var("KMS_SERVICE_URL") {
                let client = reqwest::Client::new();
                let url = format!("{}/api/v1/admin/identities", service_url.trim_end_matches('/'));
                let body = serde_json::json!({"cert_pem": String::from_utf8_lossy(&admin_cert_pem), "role": "SUPER_ADMIN"});
                match client.post(&url).json(&body).send().await {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            println!("[PKI] Admin identity registered with kms-service at {}", url);
                        } else {
                            println!("[PKI] Failed to register admin identity: HTTP {}", resp.status());
                        }
                    }
                    Err(err) => println!("[PKI] Error contacting kms-service: {}", err),
                }
            }
        }
        HsmResponse::Error { code, message } => {
            bail!("vHSM error during BootstrapPki [{code}]: {message}")
        }
        other => bail!("Unexpected vHSM response to BootstrapPki: {other:?}"),
    }

    println!("\n[SUCCESS] PKI bootstrap completed. Please keep admin.key secure.");

    Ok(())
}
