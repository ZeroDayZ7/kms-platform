use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "kms-ceremony-cli")]
#[command(about = "Offline KMS Key Ceremony CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Generate a new master key, encrypt the storage key, and split the master key into shares.
    Generate {
        #[arg(short = 's', long, default_value_t = 5)]
        shares: u8,

        #[arg(short = 't', long, default_value_t = 3)]
        threshold: u8,

        #[arg(short = 'o', long, default_value = "./out")]
        output_dir: PathBuf,
    },

    /// Recover the master key from a directory containing share JSON files.
    Recover {
        #[arg(short = 'd', long, value_name = "DIR", default_value = "./out/shares")]
        shares_dir: PathBuf,

        #[arg(
            short = 'k',
            long,
            value_name = "FILE",
            default_value = "./recovered.key"
        )]
        output_key: PathBuf,
    },

    /// Run the step-by-step interactive key ceremony prompting at the terminal.
    Interactive {
        #[arg(short = 'o', long, default_value = "./out")]
        output_dir: PathBuf,
    },
}
