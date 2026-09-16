use anyhow::{Context, Result};
use fd_lock::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use tempfile::NamedTempFile;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSecret {
    pub key: String,
    pub namespace: String,
    pub encrypted_value_hex: String,
    pub nonce_hex: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultDatabase {
    pub vault_name: String,
    pub version: String,
    pub created_at: String,
    pub kdf_salt_hex: String,
    pub root_provider: String,
    pub encrypted_hsm_state_hex: Option<String>,
    pub hsm_nonce_hex: Option<String>,
    pub secrets: HashMap<String, StoredSecret>,
}

impl VaultDatabase {
    pub fn new(vault_name: &str, kdf_salt_hex: String, root_provider: String) -> Self {
        Self {
            vault_name: vault_name.to_string(),
            version: "2.0.0".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            kdf_salt_hex,
            root_provider,
            encrypted_hsm_state_hex: None,
            hsm_nonce_hex: None,
            secrets: HashMap::new(),
        }
    }
}

pub struct VaultStorage {
    db_path: PathBuf,
}

impl VaultStorage {
    pub fn new(db_path: PathBuf) -> Self {
        Self { db_path }
    }

    pub fn save(&self, db: &VaultDatabase) -> Result<()> {
        let parent = self
            .db_path
            .parent()
            .context("Invalid parent directory for vault database")?;
        fs::create_dir_all(parent)?;

        let content = serde_json::to_vec_pretty(db)?;
        let mut temp_file = NamedTempFile::new_in(parent)?;
        temp_file.write_all(&content)?;
        temp_file.flush()?;
        temp_file.persist(&self.db_path)?;
        Ok(())
    }

    pub fn load(&self) -> Result<VaultDatabase> {
        let file = File::open(&self.db_path)
            .with_context(|| format!("Failed to open vault database at {:?}", self.db_path))?;
        let lock = RwLock::new(file);
        let guard = lock.read().context("Failed to acquire read lock on vault database")?;
        let mut contents = Vec::new();
        (&*guard).read_to_end(&mut contents)?;
        let db: VaultDatabase = serde_json::from_slice(&contents)?;
        Ok(db)
    }

    pub fn exists(&self) -> bool {
        self.db_path.exists()
    }
}
