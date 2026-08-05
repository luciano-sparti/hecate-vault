use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "hecate",
    author = "Luciano",
    version = "0.1.0",
    about = "Hecate Vault — Local-first, TPM-backed encrypted secrets CLI"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new Hecate Vault
    Init {
        #[arg(short, long, default_value = "default")]
        vault: String,
    },
    /// Check the lock/hardware status of the vault
    Status,
    /// Store a secret in the vault
    Set {
        /// Secret key identifier (e.g. 'db_password' or 'dev/aws_key')
        key: String,
        /// Secret value
        #[arg(short, long)]
        value: Option<String>,
        /// Namespace for grouping
        #[arg(short, long, default_value = "default")]
        namespace: String,
    },
    /// Retrieve a secret from the vault
    Get {
        /// Secret key identifier
        key: String,
        /// Namespace
        #[arg(short, long, default_value = "default")]
        namespace: String,
    },
    /// List stored secret keys
    List {
        /// Optional namespace filter
        #[arg(short, long)]
        namespace: Option<String>,
    },
    /// Delete a secret from the vault
    Delete {
        /// Secret key identifier
        key: String,
        /// Namespace
        #[arg(short, long, default_value = "default")]
        namespace: String,
    },
    /// Rotate the vault Master Key or individual secret key
    Rotate,
    /// View tamper-evident audit logs
    Audit,
    /// Execute a subprocess with injected secrets
    Exec {
        /// Secret namespace to inject into env
        #[arg(short, long, default_value = "default")]
        namespace: String,
        /// Command to execute
        command: String,
        /// Arguments for the command
        #[arg(raw = true)]
        args: Vec<String>,
    },
}
