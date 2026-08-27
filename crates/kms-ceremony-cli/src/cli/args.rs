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
    /// Interaktywna ceremonia generowania klucza głównego bezpośrednio w pamięci vHSM
    Interactive {
        #[arg(
            short,
            long,
            help = "Ścieżka do gniazda Unix vHSM",
            env = "CRYPTO__HSM_SOCKET_PATH",
            default_value = "/run/vhsm/vhsm.sock"
        )]
        socket_path: String,

        #[arg(
            short = 's',
            long,
            default_value_t = 5,
            help = "Całkowita liczba udziałów"
        )]
        shares: u8,

        #[arg(
            short = 't',
            long,
            default_value_t = 3,
            help = "Próg wymaganych udziałów (K)"
        )]
        threshold: u8,

        #[arg(
            short = 'o',
            long,
            default_value = "./out",
            help = "Katalog wyjściowy na pliki udziałów"
        )]
        output_dir: PathBuf,
    },

    /// Odblokowuje (Unseal) HSM, wczytując udziały z katalogu lub wprowadzając je interaktywnie
    Unseal {
        #[arg(
            short,
            long,
            help = "Ścieżka do gniazda Unix vHSM",
            env = "CRYPTO__HSM_SOCKET_PATH",
            default_value = "/run/vhsm/vhsm.sock"
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
            short = 'd',
            long = "shares-dir",
            help = "Katalog z plikami JSON udziałów",
            default_value = "./out/shares"
        )]
        shares_dir: PathBuf,

        /// Bezpośrednie ścieżki do plików udziałów JSON (można podać wiele razy)
        #[arg(short = 'f', long = "file")]
        share_files: Vec<PathBuf>,
    },

    /// Szyfruje podany tekst za pomocą klucza HSM
    Encrypt {
        #[arg(
            short,
            long,
            env = "CRYPTO__HSM_SOCKET_PATH",
            default_value = "/run/vhsm/vhsm.sock"
        )]
        socket_path: String,

        #[arg(short, long, help = "Dane jawne w postaci tekstu")]
        plaintext: String,
    },

    /// Odszyfrowuje szyfrogram (zawierający 12-bajtowy nonce na początku)
    Decrypt {
        #[arg(
            short,
            long,
            env = "CRYPTO__HSM_SOCKET_PATH",
            default_value = "/run/vhsm/vhsm.sock"
        )]
        socket_path: String,

        #[arg(short, long, help = "Szyfrogram w formacie HEX (Nonce + Ciphertext)")]
        ciphertext_hex: String,
    },

    /// Weryfikuje spójność łańcucha audytowego w bazie danych
    VerifyAuditChain {
        #[arg(
            short,
            long,
            help = "Base URL of kms-service (e.g. http://localhost:8080)",
            env = "KMS_SERVICE_URL"
        )]
        service_url: Option<String>,

        /// Number of records to verify (default 1000). Use `full` to verify from genesis.
        #[arg(short = 'n', long = "limit")]
        limit: Option<usize>,

        /// Verify from genesis (ignore limit)
        #[arg(short = 'F', long = "full")]
        full: bool,
    },
}
