use anyhow::Result;
use clap::Parser;
use kms_ceremony_cli::cli::args::{CliArgs, Commands};
use kms_ceremony_cli::cli::ceremony::handle_interactive_ceremony;
use kms_ceremony_cli::cli::crypto_ops::{handle_decrypt, handle_encrypt};
use kms_ceremony_cli::cli::unseal::handle_unseal_hsm;
use kms_ceremony_cli::cli::verify_audit::handle_verify_audit;

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
            share_files,
        } => {
            handle_unseal_hsm(socket_path, threshold, shares_dir, share_files).await?;
        }

        Commands::Encrypt {
            socket_path,
            plaintext,
        } => {
            handle_encrypt(socket_path, plaintext).await?;
        }

        Commands::Decrypt {
            socket_path,
            ciphertext_hex,
        } => {
            handle_decrypt(socket_path, ciphertext_hex).await?;
        }

        Commands::VerifyAuditChain {
            service_url,
            limit,
            full,
        } => {
            handle_verify_audit(service_url, None, limit, full).await?;
        }
    }

    Ok(())
}
