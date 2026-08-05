use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metadata for a single vault secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub key_name: String,
    pub namespace: String,
    pub created_at: String,
    pub updated_at: String,
    pub version: u32,
    pub tags: Vec<String>,
}

/// Encrypted secret payload holding wrapped DEK and encrypted ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecretEntry {
    pub metadata: SecretMetadata,
    pub salt: String,       // Base64-encoded salt
    pub nonce: String,      // Base64-encoded AEAD nonce
    pub ciphertext: String, // Base64-encoded ciphertext
}

/// Root Hecate Vault file format schema stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    pub vault_name: String,
    pub version: String,
    pub created_at: String,
    pub kdf_salt: String,        // Base64 salt for Master Key
    pub hardware_sealed: bool,  // Whether Master Key is sealed in TPM / OS Keyring
    pub root_provider: String,   // "tpm2", "dpapi", "keyring", or "passphrase"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultDatabase {
    pub header: VaultHeader,
    pub secrets: HashMap<String, EncryptedSecretEntry>, // "namespace/key" -> Entry
}

impl VaultDatabase {
    pub fn new(vault_name: &str, kdf_salt_b64: String, root_provider: String) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            header: VaultHeader {
                vault_name: vault_name.to_string(),
                version: "1.0.0".to_string(),
                created_at: now,
                kdf_salt: kdf_salt_b64,
                hardware_sealed: root_provider != "passphrase",
                root_provider,
            },
            secrets: HashMap::new(),
        }
    }

    pub fn full_key(namespace: &str, key_name: &str) -> String {
        format!("{}/{}", namespace, key_name)
    }
}
