use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "kms-ceremony-cli",
    author,
    version,
    about = "KMS Key Ceremony & vHSM CLI Tool"
)]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    // --- OFFLINE CEREMONY COMMANDS ---
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

    // --- DAEMON / HSM INTERACTION COMMANDS ---
    /// Inicjalizuje HSM kluczem głównym z odzyskanych udziałów Shamira
    InitMasterKey {
        #[arg(
            short,
            long,
            help = "Ścieżka do gniazda Unix vHSM",
            default_value = "/tmp/vhsm.sock"
        )]
        socket_path: String,

        #[arg(
            short,
            long,
            help = "Próg wymaganych udziałów (K)",
            default_value_t = 3
        )]
        threshold: u8,

        #[arg(
            short,
            long = "share",
            help = "Udziały w formacie hex (podaj wielokrotnie)",
            required = true
        )]
        shares: Vec<String>,
    },

    /// Szyfruje podany tekst za pomocą klucza HSM
    Encrypt {
        #[arg(short, long, default_value = "/tmp/vhsm.sock")]
        socket_path: String,

        #[arg(short, long, help = "Dane jawne w postaci tekstu")]
        plaintext: String,
    },

    /// Odszyfrowuje szyfrogram (zawierający 12-bajtowy nonce na początku)
    Decrypt {
        #[arg(short, long, default_value = "/tmp/vhsm.sock")]
        socket_path: String,

        #[arg(short, long, help = "Szyfrogram w formacie HEX (Nonce + Ciphertext)")]
        ciphertext_hex: String,
    },
}
