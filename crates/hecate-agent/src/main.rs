mod cli;
mod client;
mod compliance;
mod guard;
mod sync;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use cli::{Cli, Commands};
use client::AgentClient;
use colored::Colorize;
use compliance::ComplianceAuditor;
use guard::{FileGuard, ProcessContext};
use hecate_crypto::SecretBuffer;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use sync::PolicySynchronizer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub core_url: String,
    pub agent_id: String,
    pub client_certificate_pem: String,
    pub ca_certificate_pem: String,
    pub core_signing_public_key_hex: String,
    pub cert_expires_at: i64,
}

fn resolve_config_dir(custom_dir: Option<String>) -> Result<PathBuf> {
    if let Some(dir) = custom_dir {
        let p = PathBuf::from(dir);
        fs::create_dir_all(&p)?;
        Ok(p)
    } else {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .context("Could not determine home directory")?;
        let dir = PathBuf::from(home).join(".hecate-agent");
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    let config_dir = resolve_config_dir(args.config_dir)?;
    let config_file = config_dir.join("agent_config.json");

    match args.command {
        Commands::Enroll { core, token } => {
            println!("{} Enrolling Agent with Core at '{}'...", "🔐".green(), core.cyan());
            let hostname = std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("COMPUTERNAME"))
                .unwrap_or_else(|_| "node-01".to_string());
            let os_info = std::env::consts::OS.to_string();

            let mut client = AgentClient::connect(core.clone()).await?;
            let res = client.enroll(token, hostname.clone(), os_info).await?;

            let config = AgentConfig {
                core_url: core,
                agent_id: res.agent_id.clone(),
                client_certificate_pem: res.client_certificate_pem,
                ca_certificate_pem: res.ca_certificate_pem,
                core_signing_public_key_hex: res.core_signing_public_key,
                cert_expires_at: res.cert_expires_at,
            };

            let serialized = serde_json::to_string_pretty(&config)?;
            fs::write(&config_file, serialized)?;

            println!("{} Enrollment successful!", "✓".green());
            println!("  Assigned Agent ID: {}", res.agent_id.yellow().bold());
            println!("  Config saved to: {:?}", config_file);
        }

        Commands::Run { once } => {
            if !config_file.exists() {
                return Err(anyhow!("Agent is not enrolled. Run 'hecate-agent enroll --core <URL> --token <TOKEN>' first."));
            }

            let contents = fs::read_to_string(&config_file)?;
            let config: AgentConfig = serde_json::from_str(&contents)?;

            println!("{}", "═════════════════════════════════════════════════════".cyan());
            println!("  {} {}", "🛡️ ".green(), "Hecate Agent Compliance & Guard Daemon".bold());
            println!("  Agent ID: {}", config.agent_id.yellow());
            println!("  Connected Core: {}", config.core_url.cyan());
            println!("{}", "═════════════════════════════════════════════════════".cyan());

            let mut client = AgentClient::connect(config.core_url.clone()).await?;
            let mut sync_engine = PolicySynchronizer::new(config.core_signing_public_key_hex.clone());

            loop {
                // Heartbeat
                let _ = client.heartbeat(config.agent_id.clone(), 0).await;

                // Sync Policies
                let sync_res = client.sync_policies(config.agent_id.clone(), 0).await;
                if let Ok(res) = sync_res {
                    if let Ok(policies) = sync_engine.verify_and_apply_envelopes(&res.signed_policies) {
                        println!("{} Synchronized {} active policies from Core", "✓".green(), policies.len());
                        let compliance_items = ComplianceAuditor::audit_all(&policies, &HashMap::new());
                        let _ = client.report_compliance(config.agent_id.clone(), compliance_items).await;
                    }
                }

                if once {
                    break;
                }

                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
        }

        Commands::Status => {
            if !config_file.exists() {
                println!("{} Agent is not enrolled.", "✗".red());
                return Ok(());
            }

            let contents = fs::read_to_string(&config_file)?;
            let config: AgentConfig = serde_json::from_str(&contents)?;

            println!("{}", "=== Hecate Agent Status ===".cyan().bold());
            println!("  Agent ID: {}", config.agent_id.yellow());
            println!("  Core Endpoint: {}", config.core_url.cyan());
            println!("  Cert Expiration: {}", chrono::DateTime::from_timestamp(config.cert_expires_at, 0).unwrap_or_default());
            println!("  Status: {}", "ONLINE / COMPLIANT".green().bold());
        }

        Commands::Protect {
            source,
            dest,
            key_id,
            passphrase,
        } => {
            let pass = passphrase.unwrap_or_else(|| "default_guard_passphrase".to_string());
            FileGuard::encrypt_file(
                Path::new(&source),
                Path::new(&dest),
                &key_id,
                &SecretBuffer::from_str(&pass),
            )?;

            println!("{} File '{}' encrypted and protected -> '{}'", "✓".green(), source.cyan(), dest.yellow());
        }

        Commands::Unprotect {
            source,
            dest,
            passphrase,
        } => {
            let pass = passphrase.unwrap_or_else(|| "default_guard_passphrase".to_string());
            FileGuard::decrypt_file(
                Path::new(&source),
                Path::new(&dest),
                &SecretBuffer::from_str(&pass),
            )?;

            println!("{} File '{}' unprotected and decrypted -> '{}'", "✓".green(), source.cyan(), dest.yellow());
        }

        Commands::Exec { path, command, args } => {
            let ctx = ProcessContext::current();
            println!("{} Evaluating process credentials (UID: {}, Binary: {})...", "🔍".cyan(), ctx.uid, ctx.binary_path);

            // Execute subprocess
            let mut cmd = Command::new(&command);
            cmd.args(&args);
            cmd.env("HECATE_GUARD_ACTIVE", "1");
            cmd.env("HECATE_GUARD_PATH", &path);

            let status = cmd.status().context(format!("Failed to execute '{}'", command))?;
            println!("{} Process exited with code {}", "✓".green(), status.code().unwrap_or(-1));
        }
    }

    Ok(())
}
