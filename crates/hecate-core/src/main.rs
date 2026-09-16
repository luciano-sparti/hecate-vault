use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use hecate_core::audit::AuditLedger;
use hecate_core::cli::{AgentCommands, BackupCommands, Cli, Commands, KeyCommands, PolicyCommands};
use hecate_core::ha::backup::{create_dr_backup, restore_dr_backup};
use hecate_core::pki::InternalCertificateAuthority;
use hecate_core::secrets::{VaultDatabase, VaultStorage};
use hecate_core::server::HecateCoreServer;
use hecate_core::{load_or_init_core_state, resolve_base_dir};
use hecate_crypto::{
    derive_key_argon2id, detect_root_trust, generate_salt, split_secret,
    KeyType, PolicySigner, SecretBuffer,
};
use hecate_protocol::admin::admin_service_server::AdminServiceServer;
use hecate_protocol::agent::agent_service_server::AgentServiceServer;
use hecate_protocol::hsm::hsm_crypto_service_server::HsmCryptoServiceServer;
use hecate_protocol::policy::{GuardPointPolicy, PermissionAction, PolicyRule, PolicySubject, SubjectType};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    let base_dir = resolve_base_dir(args.data_dir)?;

    match args.command {
        Commands::Init {
            passphrase,
            shares,
            threshold,
        } => {
            println!("{} Initializing Hecate Core & Software HSM...", "🔐".green());
            let provider = detect_root_trust();
            println!("  Root of Trust Provider: {}", provider.to_string().yellow());

            let pass = passphrase.unwrap_or_else(|| "default_master_passphrase_hecate_vault".to_string());
            let salt = generate_salt();
            let master_key = derive_key_argon2id(&SecretBuffer::from_str(&pass), &salt)?;

            let db = VaultDatabase::new("hecate-core-primary", hex::encode(&salt), provider.to_string());
            let storage = VaultStorage::new(base_dir.join("vault.json"));
            storage.save(&db)?;

            let mut audit_ledger = AuditLedger::open_or_create(&base_dir.join("audit.log"))?;
            audit_ledger.append("INIT_CORE", "admin", "Initialized Hecate Core HSM and Vault")?;

            let _ = InternalCertificateAuthority::generate_or_load(&base_dir.join("pki.json"))?;
            let signer = PolicySigner::generate();
            fs::write(base_dir.join("signing_key.hex"), hex::encode(signer.to_bytes()))?;

            println!("{} Core initialized successfully in {:?}", "✓".green(), base_dir);

            if threshold > 1 && shares >= threshold {
                println!("\n{} Generating Shamir Disaster Recovery Key Shares ({}-of-{} quorum)...", "🛡️ ".cyan(), threshold, shares);
                let key_shares = split_secret(&master_key, threshold, shares)?;
                for share in key_shares {
                    println!("  Share #{}: {}", share.id, share.to_formatted_string().bold().magenta());
                }
                println!("\n{} Store these shares in distinct physical/offline locations!", "WARNING:".yellow().bold());
            }
        }

        Commands::Server { listen } => {
            let addr: SocketAddr = listen.parse().context("Invalid server listen address")?;
            let state = load_or_init_core_state(&base_dir)?;
            let core_server = HecateCoreServer::new(state);

            println!("{}", "═════════════════════════════════════════════════════".cyan());
            println!("  {} {}", "🛡️ ".green(), "Hecate Core Management Server & Software HSM".bold());
            println!("  Listening on: {}", listen.green().bold());
            println!("  Data Directory: {:?}", base_dir);
            println!("{}", "═════════════════════════════════════════════════════".cyan());

            Server::builder()
                .add_service(AdminServiceServer::new(core_server.clone()))
                .add_service(AgentServiceServer::new(core_server.clone()))
                .add_service(HsmCryptoServiceServer::new(core_server))
                .serve(addr)
                .await?;
        }

        Commands::Key { action } => {
            let state_arc = load_or_init_core_state(&base_dir)?;
            match action {
                KeyCommands::Create { alias, key_type } => {
                    let mut state = state_arc.write().await;
                    let kt = match key_type.to_lowercase().as_str() {
                        "chacha20poly1305" => KeyType::ChaCha20Poly1305,
                        "hmacsha256" => KeyType::HmacSha256,
                        _ => KeyType::Aes256Gcm,
                    };
                    let meta = state.hsm.generate_key(&alias, kt, HashMap::new())?;
                    state.audit_ledger.append("CLI_GENERATE_KEY", "admin", &format!("Key ID: {}, Alias: {}", meta.key_id, meta.key_alias))?;
                    state.persist()?;
                    println!("{} Created key '{}' (ID: {}, Version: {})", "✓".green(), meta.key_alias.cyan(), meta.key_id.yellow(), meta.current_version);
                }
                KeyCommands::Rotate { id } => {
                    let mut state = state_arc.write().await;
                    let new_ver = state.hsm.rotate_key(&id)?;
                    state.audit_ledger.append("CLI_ROTATE_KEY", "admin", &format!("Rotated key ID: {}, New Version: {}", id, new_ver))?;
                    state.persist()?;
                    println!("{} Rotated key '{}' to version {}", "✓".green(), id.yellow(), new_ver);
                }
                KeyCommands::List => {
                    let state = state_arc.read().await;
                    let keys = state.hsm.list_keys();
                    println!("{}", "=== HSM Managed Keys ===".cyan().bold());
                    if keys.is_empty() {
                        println!("  No keys found in HSM.");
                    } else {
                        for k in keys {
                            println!("  • ID: {} | Alias: {} | Ver: {} | State: {:?}", k.key_id.yellow(), k.key_alias.cyan(), k.current_version, k.state);
                        }
                    }
                }
            }
        }

        Commands::Policy { action } => {
            let state_arc = load_or_init_core_state(&base_dir)?;
            match action {
                PolicyCommands::Add {
                    id,
                    name,
                    target_path,
                    backing_path,
                    key_id,
                    deny_root,
                    uids,
                    binary_hashes,
                } => {
                    let mut state = state_arc.write().await;
                    let mut subjects = Vec::new();
                    for uid in uids {
                        subjects.push(PolicySubject {
                            subject_type: SubjectType::Uid as i32,
                            identifier: uid,
                        });
                    }
                    for hash in binary_hashes {
                        subjects.push(PolicySubject {
                            subject_type: SubjectType::BinaryHash as i32,
                            identifier: hash,
                        });
                    }

                    let rule = PolicyRule {
                        rule_id: format!("rule-{}", id),
                        subjects,
                        action: PermissionAction::ActionReadWrite as i32,
                        allow: true,
                    };

                    let policy = GuardPointPolicy {
                        policy_id: id.clone(),
                        policy_name: name.clone(),
                        target_path: target_path.clone(),
                        backing_path: backing_path.clone(),
                        key_id: key_id.clone(),
                        deny_root_unauthorized: deny_root,
                        rules: vec![rule],
                        policy_version: 1,
                        updated_at: chrono::Utc::now().timestamp(),
                    };

                    let pol_id = state.policy_store.add_or_update_policy(policy);
                    state.persist()?;
                    state.audit_ledger.append("CLI_ADD_POLICY", "admin", &format!("Policy: {}", pol_id))?;

                    println!("{} Guard Point policy '{}' registered (Target: {})", "✓".green(), pol_id.cyan(), target_path.yellow());
                }
                PolicyCommands::List => {
                    let state = state_arc.read().await;
                    let policies = state.policy_store.list_policies();
                    println!("{}", "=== Guard Point Policies ===".cyan().bold());
                    if policies.is_empty() {
                        println!("  No policies configured.");
                    } else {
                        for p in policies {
                            println!("  • ID: {} | Name: {} | Target: {} | Backing: {} | DenyRoot: {}",
                                p.policy_id.yellow(), p.policy_name.cyan(), p.target_path.green(), p.backing_path, p.deny_root_unauthorized);
                        }
                    }
                }
            }
        }

        Commands::Agent { action } => {
            let state_arc = load_or_init_core_state(&base_dir)?;
            match action {
                AgentCommands::Token { hostname, validity_seconds } => {
                    let mut state = state_arc.write().await;
                    let token = state.agent_registry.generate_token(&hostname, validity_seconds);
                    state.persist()?;
                    state.audit_ledger.append("CLI_GEN_TOKEN", "admin", &format!("Token for {}", hostname))?;

                    println!("{} Enrollment Token for '{}':", "✓".green(), hostname.cyan());
                    println!("  Token: {}", token.token.bold().yellow());
                    println!("  Expires in: {} seconds", validity_seconds);
                }
                AgentCommands::List => {
                    let state = state_arc.read().await;
                    let agents = state.agent_registry.list_agents();
                    println!("{}", "=== Enrolled Agents ===".cyan().bold());
                    if agents.is_empty() {
                        println!("  No agents enrolled.");
                    } else {
                        for a in agents {
                            let status_color = if a.compliance_status == "COMPLIANT" { a.compliance_status.green() } else { a.compliance_status.red() };
                            println!("  • ID: {} | Host: {} | Status: {} | Revoked: {}", a.agent_id.yellow(), a.hostname.cyan(), status_color, a.is_revoked);
                        }
                    }
                }
                AgentCommands::Revoke { id, reason } => {
                    let mut state = state_arc.write().await;
                    state.agent_registry.revoke_agent(&id)?;
                    state.persist()?;
                    state.audit_ledger.append("CLI_REVOKE_AGENT", "admin", &format!("Agent: {}, Reason: {}", id, reason))?;
                    println!("{} Revoked agent '{}'", "✓".green(), id.yellow());
                }
            }
        }

        Commands::Compliance => {
            let state_arc = load_or_init_core_state(&base_dir)?;
            let state = state_arc.read().await;
            let agents = state.agent_registry.list_agents();
            let total = agents.len();
            let compliant = agents.iter().filter(|a| a.compliance_status == "COMPLIANT").count();

            println!("{}", "=== Compliance Posture Dashboard ===".cyan().bold());
            println!("  Total Enrolled Nodes: {}", total);
            println!("  Compliant Nodes: {}", compliant.to_string().green());
            println!("  Non-Compliant Nodes: {}", (total - compliant).to_string().red());
        }

        Commands::Audit => {
            let state_arc = load_or_init_core_state(&base_dir)?;
            let state = state_arc.read().await;
            let is_valid = state.audit_ledger.verify_chain()?;
            println!("{}", "=== Tamper-Evident Hash Chain Audit Log ===".cyan().bold());
            println!("  Chain Integrity Proof: {}\n", if is_valid { "VALID ✓".green().bold() } else { "COMPROMISED ✗".red().bold() });

            for entry in state.audit_ledger.entries() {
                println!("  [{}] {} | Actor: {} | Action: {} | Hash: {}",
                    entry.index, entry.timestamp.cyan(), entry.actor.yellow(), entry.action.green().bold(), &entry.entry_hash[..16]);
                println!("      Details: {}", entry.details);
            }
        }

        Commands::Backup { action } => {
            let state_arc = load_or_init_core_state(&base_dir)?;
            match action {
                BackupCommands::Create { out } => {
                    let state = state_arc.read().await;
                    let payload = serde_json::to_vec(&state.vault_db)?;
                    let (archive, sha256) = create_dr_backup(&payload, &SecretBuffer::from_str("disaster_recovery_master_pass"))?;
                    fs::write(&out, archive)?;
                    println!("{} DR Backup created at '{}' (SHA-256: {})", "✓".green(), out.cyan(), sha256.yellow());
                }
                BackupCommands::Restore { file } => {
                    let mut state = state_arc.write().await;
                    let archive_bytes = fs::read(&file)?;
                    let restored = restore_dr_backup(&archive_bytes, &SecretBuffer::from_str("disaster_recovery_master_pass"))?;
                    let db: VaultDatabase = serde_json::from_slice(&restored)?;
                    state.vault_db = db;
                    state.persist()?;
                    println!("{} Core successfully restored from '{}'", "✓".green(), file.cyan());
                }
            }
        }

        Commands::Tui => {
            hecate_core::run_tui_app(&base_dir).await?;
        }
    }

    Ok(())
}
