mod audit;
mod cli;
mod crypto;
mod exec;
mod storage;
mod tpm;
mod vault;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use colored::Colorize;
use tpm::detect_root_trust;

fn main() -> Result<()> {
    let args = Cli::parse();
    let trust_provider = detect_root_trust();

    match args.command {
        Commands::Init { vault } => {
            println!(
                "{} initializing Hecate Vault '{}'...",
                "🔑".green(),
                vault.bold()
            );
            println!(
                "{} Root of Trust provider detected: {}",
                "🛡️ ".cyan(),
                trust_provider.to_string().yellow()
            );
        }
        Commands::Status => {
            println!("{}", "=== Hecate Vault Status ===".bold().cyan());
            println!("  Root of Trust: {}", trust_provider.to_string().yellow());
            println!("  Vault Location: ~/.hecate/vault.json");
            println!("  Status: {}", "Ready".green());
        }
        Commands::Set { key, value: _, namespace } => {
            println!(
                "{} Setting secret '{}' in namespace '{}'...",
                "🔒".green(),
                key.bold(),
                namespace.cyan()
            );
        }
        Commands::Get { key, namespace } => {
            println!(
                "{} Retrieving secret '{}' from namespace '{}'...",
                "🔑".green(),
                key.bold(),
                namespace.cyan()
            );
        }
        Commands::List { namespace } => {
            println!(
                "{} Listing secrets (namespace: {})...",
                "📋".cyan(),
                namespace.unwrap_or_else(|| "all".to_string()).yellow()
            );
        }
        Commands::Delete { key, namespace } => {
            println!(
                "{} Deleted secret '{}' from namespace '{}'.",
                "🗑️ ".red(),
                key.bold(),
                namespace.cyan()
            );
        }
        Commands::Rotate => {
            println!("{} Rotating Master Key...", "🔄".yellow());
        }
        Commands::Audit => {
            println!("{} Viewing tamper-evident audit logs...", "📜".magenta());
        }
        Commands::Exec { namespace, command, args } => {
            println!(
                "{} Injecting namespace '{}' secrets into subprocess: {} {}",
                "⚡".green(),
                namespace.cyan(),
                command.bold(),
                args.join(" ")
            );
        }
    }

    Ok(())
}
