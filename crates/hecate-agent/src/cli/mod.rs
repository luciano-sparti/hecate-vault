use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "hecate-agent",
    author = "Luciano",
    version = "0.2.0",
    about = "Hecate Agent — Endpoint Compliance & Guard Point Path Encryption Daemon"
)]
pub struct Cli {
    #[arg(long, global = true)]
    pub config_dir: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Enroll the Agent with a Hecate Core cluster using a One-Time Enrollment Token
    Enroll {
        #[arg(short, long)]
        core: String,
        #[arg(short, long)]
        token: String,
    },
    /// Run the Agent daemon loop (sync policies, heartbeat, compliance scan)
    Run {
        #[arg(long, default_value_t = false)]
        once: bool,
    },
    /// Show local Agent status, active Guard Points, and compliance health
    Status,
    /// Encrypt a file into a Hecate Guarded envelope
    Protect {
        #[arg(short, long)]
        source: String,
        #[arg(short, long)]
        dest: String,
        #[arg(short, long)]
        key_id: String,
        #[arg(short, long)]
        passphrase: Option<String>,
    },
    /// Decrypt a Hecate Guarded envelope file
    Unprotect {
        #[arg(short, long)]
        source: String,
        #[arg(short, long)]
        dest: String,
        #[arg(short, long)]
        passphrase: Option<String>,
    },
    /// Execute a command within an authorized Guard Point access context
    Exec {
        #[arg(short, long)]
        path: String,
        command: String,
        #[arg(raw = true)]
        args: Vec<String>,
    },
}
