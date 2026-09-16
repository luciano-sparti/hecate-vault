use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "hecate-core",
    author = "Luciano",
    version = "0.2.0",
    about = "Hecate Core — Enterprise Software HSM & Management System"
)]
pub struct Cli {
    #[arg(short, long, global = true)]
    pub data_dir: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize the Software HSM Master Key and Vault Storage
    Init {
        #[arg(short, long)]
        passphrase: Option<String>,
        #[arg(long, default_value = "1")]
        shares: u8,
        #[arg(long, default_value = "1")]
        threshold: u8,
    },
    /// Start the Core gRPC + mTLS Management Server
    Server {
        #[arg(short, long, default_value = "127.0.0.1:50051")]
        listen: String,
    },
    /// Key management operations
    Key {
        #[command(subcommand)]
        action: KeyCommands,
    },
    /// Guard point policy operations
    Policy {
        #[command(subcommand)]
        action: PolicyCommands,
    },
    /// Agent registration and monitoring operations
    Agent {
        #[command(subcommand)]
        action: AgentCommands,
    },
    /// Compliance monitoring dashboard
    Compliance,
    /// Audit ledger verification and log inspection
    Audit,
    /// Disaster Recovery Backup and Restoration
    Backup {
        #[command(subcommand)]
        action: BackupCommands,
    },
    /// Launch the Interactive Terminal User Interface (TUI)
    Tui,
}

#[derive(Subcommand, Debug)]
pub enum KeyCommands {
    /// Generate a new key inside the HSM
    Create {
        #[arg(short, long)]
        alias: String,
        #[arg(short = 't', long, default_value = "aes256gcm")]
        key_type: String,
    },
    /// Rotate an existing key to a new version
    Rotate {
        #[arg(short, long)]
        id: String,
    },
    /// List all HSM keys
    List,
}

#[derive(Subcommand, Debug)]
pub enum PolicyCommands {
    /// Add or update a Guard Point policy
    Add {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        target_path: String,
        #[arg(long)]
        backing_path: String,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        deny_root: bool,
        #[arg(long, value_delimiter = ',')]
        uids: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        binary_hashes: Vec<String>,
    },
    /// List all Guard Point policies
    List,
}

#[derive(Subcommand, Debug)]
pub enum AgentCommands {
    /// Generate a One-Time Enrollment Token (OTET) for a new agent node
    Token {
        #[arg(long)]
        hostname: String,
        #[arg(short, long, default_value_t = 3600)]
        validity_seconds: i64,
    },
    /// List enrolled agents and their current compliance status
    List,
    /// Revoke an agent's access
    Revoke {
        #[arg(short, long)]
        id: String,
        #[arg(short, long)]
        reason: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum BackupCommands {
    /// Create an encrypted Disaster Recovery backup archive
    Create {
        #[arg(short, long)]
        out: String,
    },
    /// Restore the Core from an encrypted Disaster Recovery backup
    Restore {
        #[arg(short, long)]
        file: String,
    },
}
