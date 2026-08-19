mod cli;
mod crypto;
mod storage;

use anyhow::{bail, Result};
use clap::Parser;
use std::fs;
use std::path::PathBuf;

use crate::cli::args::{Cli, Commands};
use crate::crypto::keys::{encrypt_storage_key, generate_master_key};
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
        let file_path = write_share_file(
            &share_dir,
            *index,
            threshold,
            shares,
            share_hex.clone(),
        )?;
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

    println!("[OK] Generated master key, storage key, and SSS shares in {}", output_dir.display());
    println!("[OK] Share files created in {}", share_dir.display());
    println!("[OK] Ceremony manifest written to {}", output_dir.join("ceremony_manifest.json").display());

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
            sorted.len(), threshold
        );
    }

    let shares: Vec<(u8, String)> = sorted
        .iter()
        .map(|record| (record.index, record.share_hex.clone()))
        .collect();

    let recovered_key = combine_shares(&shares)?;
    write_master_key_file(&output_key, &recovered_key)?;

    println!("[OK] Reconstructed master key from {} shares", sorted.len());
    println!("[OK] Saved recovered key to {}", output_key.display());
    println!("[INFO] Threshold: {threshold}, total shares: {total_shares}");

    Ok(())
}

fn interactive_walkthrough() -> Result<()> {
    use dialoguer::{Input, Confirm};

    let shares: u8 = Input::new()
        .with_prompt("Number of shares")
        .default(5)
        .interact()?;

    let threshold: u8 = Input::new()
        .with_prompt("Recovery threshold")
        .default(3)
        .interact()?;

    let output_dir: String = Input::new()
        .with_prompt("Output directory")
        .default("./out".to_string())
        .interact()?;

    let output_dir = PathBuf::from(output_dir);
    handle_generate(shares, threshold, output_dir.clone())?;

    let recover_now = Confirm::new()
        .with_prompt("Do you want to recover the key immediately from the created shares?")
        .default(false)
        .interact()?;

    if recover_now {
        let recovered_path: String = Input::new()
            .with_prompt("Recovered key output path")
            .default("./recovered.key".to_string())
            .interact()?;
        handle_recover(output_dir.join("shares"), PathBuf::from(recovered_path))?;
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Generate { shares, threshold, output_dir }) => {
            handle_generate(shares, threshold, output_dir)?;
        }
        Some(Commands::Recover { shares_dir, output_key }) => {
            handle_recover(shares_dir, output_key)?;
        }
        Some(Commands::Interactive { output_dir }) => {
            handle_generate(5, 3, output_dir)?;
        }
        None => {
            interactive_walkthrough()?;
        }
    }

    Ok(())
}