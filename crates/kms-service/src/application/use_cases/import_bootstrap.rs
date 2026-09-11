use crate::config::acl::ControlAction;
use crate::domain::crypto::{KmsCryptoService, SecretString};
use crate::domain::keys::models::{CredentialId, ServiceId, TargetId};
use crate::errors::{AppError, AppResult};
use crate::server::state::AppState;
use chrono::Utc;
use kms_db::repositories::{AuditQueries, BootstrapQueries};
use kms_db::{Postgres, Transaction};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportBootstrapSummary {
    pub total_in_file: usize,
    pub resources_imported: usize,
    pub resources_skipped: usize,
    pub credentials_imported: usize,
    pub credentials_skipped: usize,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ImportBootstrapInput {
    pub version: u32,
    #[serde(default)]
    pub target_resources: Vec<TargetResourceRecord>,
    #[serde(default)]
    pub credentials: Vec<BootstrapCredentialRecord>,
}

#[derive(Debug, Deserialize)]
pub struct TargetResourceRecord {
    pub id: Option<Uuid>,
    pub target_name: String,
    pub target_type: String,
    pub connection_url: String,
    pub default_role: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct BootstrapCredentialRecord {
    pub id: Option<Uuid>,
    service_id: ServiceId,
    target_id: Option<TargetId>,
    credential_id: Option<CredentialId>,
    #[serde(alias = "target_type")]
    target_type: String,
    target_db: serde_json::Value,
    resource: Option<String>,
    username: String,
    password: SecretString,
    ttl_seconds: Option<u64>,
}

pub async fn import_bootstrap(
    state: AppState,
    caller_service: String,
    input: ImportBootstrapInput,
) -> AppResult<ImportBootstrapSummary> {
    info!(
        caller_service = %caller_service,
        version = input.version,
        target_resources_raw_count = input.target_resources.len(),
        credentials_raw_count = input.credentials.len(),
        "Rozpoczynam procedurę import_bootstrap"
    );

    // 1. Weryfikacja uprawnień ACL
    debug!(caller_service = %caller_service, "Weryfikacja uprawnień ACL dla BootstrapImport");
    let compiled = state.settings.acl.compile();
    if !compiled.has_control_action(
        &ServiceId(caller_service.clone()),
        &ControlAction::BootstrapImport,
    ) {
        error!(caller_service = %caller_service, "Forbidden attempt to perform BootstrapImport - ACL rejection");
        return Err(AppError::Forbidden);
    }
    debug!(caller_service = %caller_service, "ACL weryfikacja zakończona sukcesem");

    if input.version != 1 {
        warn!(
            version = input.version,
            "Odrzucono import: nieobsługiwana wersja bootstrapu"
        );
        return Err(AppError::ValidationError(
            "Unsupported bootstrap version".into(),
        ));
    }

    // Sekcje `credentials` i `target_resources` są deserializowane w extractorze.
    // Przypiszemy je bezpośrednio do lokalnych zmiennych.
    let cred_records: Vec<BootstrapCredentialRecord> = input.credentials;
    let target_records: Vec<TargetResourceRecord> = input.target_resources;

    if target_records.is_empty() && cred_records.is_empty() {
        warn!("Anulowano import: puste listy target_resources oraz credentials");
        return Err(AppError::ValidationError(
            "Nothing to import: both target_resources and credentials are empty".into(),
        ));
    }

    // 4. Rozpoczęcie atomowej transakcji w bazie
    debug!("Otwieranie transakcji w bazie danych");
    let mut tx: Transaction<'_, Postgres> = state.db.begin().await.map_err(|err| {
        error!(error = %err, "Błąd otwarcia transakcji DB");
        AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
    })?;
    debug!("Transakcja DB otwarta pomyślnie");

    let mut resources_imported = 0usize;
    let mut resources_skipped = 0usize;
    let mut credentials_imported = 0usize;
    let mut credentials_skipped = 0usize;
    let now = Utc::now();

    // ==========================================
    // KROK A: IMPORT DO target_resources
    // ==========================================
    info!(
        count = target_records.len(),
        "Rozpoczynam przetwarzanie KROK A: target_resources"
    );
    for (idx, target) in target_records.iter().enumerate() {
        let record_id = target.id.unwrap_or_else(Uuid::now_v7);
        debug!(step = "target_resource", index = idx, record_id = %record_id, target_name = %target.target_name, "Sprawdzanie istnienia rekordu w DB");

        let exists: bool = BootstrapQueries::target_resource_exists_by_id(&mut tx, record_id)
            .await
            .map_err(|err| {
                error!(error = %err, record_id = %record_id, "Błąd SQL podczas sprawdzania istnienia target_resource");
                AppError::database_error_with_source(
                    format!("Database operation failed: {err}"),
                    err,
                )
            })?;

        if exists {
            warn!(
                id = %record_id,
                target_name = %target.target_name,
                "Target resource ID już istnieje w bazie danych. Pomijam rekord."
            );
            resources_skipped += 1;
            continue;
        }

        debug!(record_id = %record_id, "Szyfrowanie connection_url dla target_resource");
        let url_bytes = target.connection_url.as_bytes().to_vec();
        let url_zero = Zeroizing::new(url_bytes);
        let encrypted = state
            .crypto_service
            .encrypt_private_key(url_zero.as_ref())
            .await
            .map_err(|e| {
                error!(error = %e, record_id = %record_id, "Błąd crypto podczas szyfrowania connection_url");
                AppError::crypto_error_with_source(
                    format!("Failed to encrypt connection_url: {}", e),
                    e,
                )
            })?;

        debug!(record_id = %record_id, ciphertext_len = encrypted.ciphertext.len(), default_role = ?target.default_role, "Wywoływanie insert_target_resource");
        let inserted = BootstrapQueries::insert_target_resource(
            &mut tx,
            record_id,
            &target.target_name,
            &target.target_type,
            &encrypted.ciphertext,
            target.default_role.as_deref(),
            now,
        )
        .await
        .map_err(|err| {
            error!(error = %err, record_id = %record_id, "Błąd SQL podczas insert_target_resource");
            AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
        })?;

        if inserted {
            resources_imported += 1;
            info!(record_id = %record_id, target_name = %target.target_name, "Pomyślnie zaimportowano target_resource");
        } else {
            resources_skipped += 1;
            warn!(record_id = %record_id, target_name = %target.target_name, "Target resource został pominięty w czasie zapisu (konflikt/duplica=on conflict)");
        }
    }

    // ==========================================
    // KROK B: IMPORT DO credentials
    // ==========================================
    info!(
        count = cred_records.len(),
        "Rozpoczynam przetwarzanie KROK B: credentials"
    );
    for (idx, rec) in cred_records.iter().enumerate() {
        let record_id = rec.id.unwrap_or_else(Uuid::now_v7);
        debug!(step = "credential", index = idx, record_id = %record_id, service_id = %rec.service_id, "Sprawdzanie istnienia rekordu w DB");

        let exists: bool = BootstrapQueries::credential_exists_by_id(&mut tx, record_id)
            .await
            .map_err(|err| {
                error!(error = %err, record_id = %record_id, "Błąd SQL podczas sprawdzania istnienia credential");
                AppError::database_error_with_source(
                    format!("Database operation failed: {err}"),
                    err,
                )
            })?;

        if exists {
            warn!(
                id = %record_id,
                service_id = %rec.service_id,
                "Credential ID już istnieje w bazie danych. Pomijam rekord."
            );
            credentials_skipped += 1;
            continue;
        }

        let target_db_str = rec.target_db.to_string().trim_matches('"').to_string();

        debug!(record_id = %record_id, service_id = %rec.service_id, "Pobieranie aktywnego KEK z DB");
        let kek_row: Option<(Uuid, i32)> =
            BootstrapQueries::latest_kek_id(&mut tx, &rec.service_id.0)
                .await
                .map_err(|err| {
                    error!(error = %err, service_id = %rec.service_id, "Błąd SQL podczas zapytania o KEK");
                    AppError::database_error_with_source(
                        format!("Database operation failed: {err}"),
                        err,
                    )
                })?;

        let (kek_id, kek_version) = match kek_row {
            Some((id, ver)) => {
                debug!(kek_id = %id, kek_version = ver, "Znaleziono aktywny KEK");
                (id, ver)
            }
            None => {
                error!(
                    service_id = %rec.service_id,
                    "BRAK AKTYWNEGO KEK dla usługi! Anulowanie transakcji bootstrapu."
                );
                let _ = tx.rollback().await;
                return Err(AppError::Internal(format!(
                    "No active KEK for service: {}",
                    rec.service_id
                )));
            }
        };

        #[derive(serde::Serialize)]
        struct CredentialPayload<'a> {
            u: &'a str,
            p: &'a str,
        }

        let payload = CredentialPayload {
            u: &rec.username,
            p: rec.password.as_str(),
        };
        let payload_bytes = serde_json::to_vec(&payload).map_err(|e| {
            error!(error = %e, "Błąd serializacji JSON payloadu poświadczeń");
            AppError::Internal(format!("Failed to serialize credential payload: {e}"))
        })?;
        let payload_zero = Zeroizing::new(payload_bytes);

        debug!(record_id = %record_id, payload_bytes_len = payload_zero.len(), "Szyfrowanie payloadu poświadczeń");
        let encrypted = state
            .crypto_service
            .encrypt_private_key(payload_zero.as_ref())
            .await
            .map_err(|e| {
                error!(error = %e, service_id = %rec.service_id, "Błąd podczas szyfrowania poświadczeń");
                AppError::crypto_error_with_source(
                    format!("Failed to encrypt credential: {}", e),
                    e,
                )
            })?;

        if encrypted.ciphertext.len() < 12 {
            error!(
                len = encrypted.ciphertext.len(),
                "Zaszyfrowany payload jest za krótki (wymagane min. 12 bajtów)"
            );
            let _ = tx.rollback().await;
            return Err(AppError::crypto_error("Encrypted payload too short"));
        }

        debug!(record_id = %record_id, ciphertext_len = encrypted.ciphertext.len(), "Zapisywanie credential do DB");
        let inserted = BootstrapQueries::insert_db_credential(
            &mut tx,
            record_id,
            &rec.service_id.0,
            &rec.target_type,
            &target_db_str,
            rec.resource.as_deref().unwrap_or(""),
            &encrypted.ciphertext,
            kek_id,
            kek_version,
            now,
        )
        .await
        .map_err(|err| {
            error!(error = %err, record_id = %record_id, "Błąd SQL podczas insert_db_credential");
            AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
        })?;

        if inserted {
            credentials_imported += 1;
            info!(record_id = %record_id, service_id = %rec.service_id, username = %rec.username, "Pomyślnie zaimportowano credential");
        } else {
            credentials_skipped += 1;
            warn!(record_id = %record_id, service_id = %rec.service_id, "Credential został pominięty w czasie zapisu (ON CONFLICT DO NOTHING)");
        }
    }

    // ==========================================
    // KROK C: REJESTRACJA W AUDIT LOG
    // ==========================================
    info!("Rozpoczynam KROK C: Rejestracja wpisu audytowego");
    let audit_id = Uuid::now_v7();
    let action = "bootstrap:import";

    debug!(audit_id = %audit_id, "Pobieranie poprzedniego hasha z audit logu");
    let prev_hash_row: Option<String> =
        AuditQueries::latest_hash_tx(&mut tx).await.map_err(|err| {
            error!(error = %err, "Błąd SQL podczas pobierania latest_hash_tx");
            AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
        })?;
    let prev_hash = prev_hash_row.as_deref().unwrap_or("");
    debug!(prev_hash = %prev_hash, "Wyznaczono bazowy prev_hash dla audytu");

    let hash = kms_core::audit::compute_audit_hash(&kms_core::audit::AuditHashInput {
        id: &audit_id.to_string(),
        caller_service: &caller_service,
        target_service: "bootstrap",
        action,
        algorithm: "bootstrap-import",
        status: "Success",
        reason: Some(&format!(
            "imported {} total records (resources + credentials)",
            resources_imported + credentials_imported
        )),
        prev_hash,
        timestamp: &now,
        request_id: None,
        operation_id: None,
        target_id: None,
        metadata: Some("bootstrap_import_v2"),
        hash_version: kms_core::audit::CURRENT_AUDIT_HASH_VERSION,
    });
    debug!(audit_id = %audit_id, computed_hash = %hash, "Obliczono hash audytowy");

    AuditQueries::insert_tx(
        &mut tx,
        kms_db::repositories::AuditInsert {
            id: audit_id,
            caller_service: caller_service.clone(),
            target_service: "bootstrap".to_string(),
            action: action.to_string(),
            algorithm: "bootstrap-import".to_string(),
            status: "Success".to_string(),
            reason: Some(format!(
                "imported {} total records (resources + credentials)",
                resources_imported + credentials_imported
            )),
            prev_hash: prev_hash.to_string(),
            hash,
            signature: Some(Vec::<u8>::new()),
            request_id: None,
            operation_id: None,
            target_id: None,
            metadata: Some("bootstrap_import_v2".to_string()),
            created_at: now,
        },
    )
    .await
    .map_err(|err| {
        error!(error = %err, audit_id = %audit_id, "Błąd podczas zapisu do rekordu audytowego w bazie!");
        AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
    })?;

    debug!("Zatwierdzanie transakcji w bazie danych (tx.commit)");
    tx.commit().await.map_err(|err| {
        error!(error = %err, "Błąd podczas wykonywania tx.commit() dla bootstrap import!");
        AppError::database_error_with_source(format!("Database operation failed: {err}"), err)
    })?;

    let total_in_file = target_records.len() + cred_records.len();
    let summary = ImportBootstrapSummary {
        total_in_file,
        resources_imported,
        resources_skipped,
        credentials_imported,
        credentials_skipped,
        message: format!(
            "Pomyślnie przetworzona operacja: zaimportowano {}/{} nowych pozycji ({} pozycji już istniało w bazie)",
            resources_imported + credentials_imported,
            total_in_file,
            resources_skipped + credentials_skipped
        ),
    };

    info!(
        total_inserted = resources_imported + credentials_imported,
        skipped = resources_skipped + credentials_skipped,
        total_in_file = total_in_file,
        audit_id = %audit_id,
        "Zatwierdzono transakcję importu bootstrapu z sukcesem"
    );
    Ok(summary)
}
