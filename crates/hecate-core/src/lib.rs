pub mod agents;
pub mod audit;
pub mod cli;
pub mod ha;
pub mod pki;
pub mod policy;
pub mod secrets;
pub mod server;
pub mod tui;

use anyhow::{Context, Result};
use hecate_crypto::{
    derive_key_argon2id, generate_salt, PolicySigner, SecretBuffer, SoftwareHsm,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

pub fn resolve_base_dir(custom_dir: Option<String>) -> Result<PathBuf> {
    if let Some(dir) = custom_dir {
        let p = PathBuf::from(dir);
        fs::create_dir_all(&p)?;
        Ok(p)
    } else {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .context("Could not determine home directory")?;
        let dir = PathBuf::from(home).join(".hecate");
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}

pub fn load_or_init_core_state(base_dir: &Path) -> Result<Arc<RwLock<server::CoreState>>> {
    let vault_storage = secrets::VaultStorage::new(base_dir.join("vault.json"));
    let vault_db = if vault_storage.exists() {
        vault_storage.load()?
    } else {
        let salt = generate_salt();
        secrets::VaultDatabase::new("primary-vault", hex::encode(salt), "tpm2".to_string())
    };

    let salt = hex::decode(&vault_db.kdf_salt_hex).unwrap_or_else(|_| generate_salt());
    let master_key = derive_key_argon2id(&SecretBuffer::from_str("default_master_passphrase_hecate_vault"), &salt)?;

    let mut hsm = SoftwareHsm::new();
    hsm.init(master_key)?;

    if let (Some(enc_hex), Some(nonce_hex)) = (&vault_db.encrypted_hsm_state_hex, &vault_db.hsm_nonce_hex) {
        let _ = hsm.import_encrypted_keys(enc_hex, nonce_hex);
    }

    let policy_store = policy::PolicyStore::load_or_create(&base_dir.join("policies.json"))?;
    let agent_registry = agents::AgentRegistry::load_or_create(&base_dir.join("agents.json"))?;
    let audit_ledger = audit::AuditLedger::open_or_create(&base_dir.join("audit.log"))?;
    let pki = pki::InternalCertificateAuthority::generate_or_load(&base_dir.join("pki.json"))?;

    let signer_key_path = base_dir.join("signing_key.hex");
    let policy_signer = if signer_key_path.exists() {
        let hex_str = fs::read_to_string(&signer_key_path)?;
        let bytes = hex::decode(hex_str.trim())?;
        PolicySigner::from_bytes(&bytes)?
    } else {
        let signer = PolicySigner::generate();
        fs::write(&signer_key_path, hex::encode(signer.to_bytes()))?;
        signer
    };

    let state = server::CoreState {
        hsm,
        vault_storage,
        vault_db,
        policy_store,
        policy_signer,
        agent_registry,
        audit_ledger,
        pki,
        base_dir: base_dir.to_path_buf(),
    };

    Ok(Arc::new(RwLock::new(state)))
}

pub async fn run_tui_app(base_dir: &Path) -> Result<()> {
    let state = load_or_init_core_state(base_dir)?;
    tui::run_tui(state).await
}
