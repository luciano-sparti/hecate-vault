use crate::buffer::SecretBuffer;
use crate::envelope::{
    decrypt_aes_gcm, encrypt_aes_gcm, generate_key_256, unwrap_key, wrap_key, KEY_SIZE_256,
};
use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    PreActive,
    Active,
    Deactivated,
    Compromised,
    Destroyed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    Aes256Gcm,
    ChaCha20Poly1305,
    HmacSha256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmKeyMetadata {
    pub key_id: String,
    pub key_alias: String,
    pub key_type: KeyType,
    pub current_version: u32,
    pub state: KeyState,
    pub created_at: String,
    pub updated_at: String,
    pub tags: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
struct ExportedKeyEntry {
    metadata: HsmKeyMetadata,
    raw_key_bytes: Vec<u8>,
}

/// An in-memory, software-isolated HSM cryptographic boundary.
/// Plaintext keys never leave this boundary unencrypted.
pub struct SoftwareHsm {
    master_key: Option<SecretBuffer>,
    keys: HashMap<String, (HsmKeyMetadata, SecretBuffer)>,
}

impl SoftwareHsm {
    /// Create a new, uninitialized Software HSM instance.
    pub fn new() -> Self {
        Self {
            master_key: None,
            keys: HashMap::new(),
        }
    }

    /// Initialize the Software HSM with a Master Key.
    pub fn init(&mut self, master_key: SecretBuffer) -> Result<()> {
        if master_key.len() != KEY_SIZE_256 {
            return Err(anyhow!("Invalid Master Key length: expected 32 bytes"));
        }
        self.master_key = Some(master_key);
        Ok(())
    }

    /// Check if the Software HSM is unlocked and initialized.
    pub fn is_initialized(&self) -> bool {
        self.master_key.is_some()
    }

    fn ensure_initialized(&self) -> Result<&SecretBuffer> {
        self.master_key
            .as_ref()
            .ok_or_else(|| anyhow!("Software HSM is locked or uninitialized"))
    }

    /// Generate and register a new key within the HSM boundary.
    pub fn generate_key(
        &mut self,
        key_alias: &str,
        key_type: KeyType,
        tags: HashMap<String, String>,
    ) -> Result<HsmKeyMetadata> {
        self.ensure_initialized()?;

        let key_id = format!("key-{}", hex::encode(&crate::envelope::generate_nonce_96()[..8]));
        let raw_key = generate_key_256();
        let now = Utc::now().to_rfc3339();

        let metadata = HsmKeyMetadata {
            key_id: key_id.clone(),
            key_alias: key_alias.to_string(),
            key_type,
            current_version: 1,
            state: KeyState::Active,
            created_at: now.clone(),
            updated_at: now,
            tags,
        };

        self.keys.insert(key_id, (metadata.clone(), raw_key));
        Ok(metadata)
    }

    /// Wrap an external or secondary DEK using an HSM-managed KEK.
    pub fn wrap_key(
        &self,
        kek_id: &str,
        dek_to_wrap: &SecretBuffer,
    ) -> Result<(Vec<u8>, Vec<u8>, u32)> {
        self.ensure_initialized()?;

        let (metadata, kek) = self
            .keys
            .get(kek_id)
            .ok_or_else(|| anyhow!("KEK with ID '{}' not found in HSM", kek_id))?;

        if metadata.state != KeyState::Active {
            return Err(anyhow!("KEK is not in Active state (current: {:?})", metadata.state));
        }

        let (wrapped_dek, nonce) = wrap_key(kek, dek_to_wrap)?;
        Ok((wrapped_dek, nonce, metadata.current_version))
    }

    /// Unwrap a DEK using an HSM-managed KEK.
    pub fn unwrap_key(
        &self,
        kek_id: &str,
        wrapped_dek: &[u8],
        nonce: &[u8],
    ) -> Result<SecretBuffer> {
        self.ensure_initialized()?;

        let (metadata, kek) = self
            .keys
            .get(kek_id)
            .ok_or_else(|| anyhow!("KEK with ID '{}' not found in HSM", kek_id))?;

        if metadata.state == KeyState::Destroyed || metadata.state == KeyState::Compromised {
            return Err(anyhow!("KEK cannot be used (state: {:?})", metadata.state));
        }

        unwrap_key(kek, wrapped_dek, nonce)
    }

    /// Encrypt plaintext data inside the HSM boundary using an HSM key.
    pub fn encrypt(
        &self,
        key_id: &str,
        plaintext: &SecretBuffer,
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, u32)> {
        self.ensure_initialized()?;

        let (metadata, key) = self
            .keys
            .get(key_id)
            .ok_or_else(|| anyhow!("Key with ID '{}' not found in HSM", key_id))?;

        if metadata.state != KeyState::Active {
            return Err(anyhow!("Key is not Active for encryption (state: {:?})", metadata.state));
        }

        let (ciphertext, nonce) = encrypt_aes_gcm(key, plaintext, aad)?;
        Ok((ciphertext, nonce, metadata.current_version))
    }

    /// Decrypt ciphertext data inside the HSM boundary using an HSM key.
    pub fn decrypt(
        &self,
        key_id: &str,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<SecretBuffer> {
        self.ensure_initialized()?;

        let (metadata, key) = self
            .keys
            .get(key_id)
            .ok_or_else(|| anyhow!("Key with ID '{}' not found in HSM", key_id))?;

        if metadata.state == KeyState::Destroyed || metadata.state == KeyState::Compromised {
            return Err(anyhow!("Key cannot be used for decryption (state: {:?})", metadata.state));
        }

        decrypt_aes_gcm(key, nonce, ciphertext, aad)
    }

    /// Rotate an HSM key by generating new key bytes and incrementing the version.
    pub fn rotate_key(&mut self, key_id: &str) -> Result<u32> {
        self.ensure_initialized()?;

        let (metadata, key) = self
            .keys
            .get_mut(key_id)
            .ok_or_else(|| anyhow!("Key with ID '{}' not found in HSM", key_id))?;

        let new_key_bytes = generate_key_256();
        *key = new_key_bytes;
        metadata.current_version += 1;
        metadata.updated_at = Utc::now().to_rfc3339();

        Ok(metadata.current_version)
    }

    /// Destroy an HSM key, securely wiping its memory buffer.
    pub fn destroy_key(&mut self, key_id: &str) -> Result<()> {
        self.ensure_initialized()?;

        let (metadata, key) = self
            .keys
            .get_mut(key_id)
            .ok_or_else(|| anyhow!("Key with ID '{}' not found in HSM", key_id))?;

        *key = SecretBuffer::empty();
        metadata.state = KeyState::Destroyed;
        metadata.updated_at = Utc::now().to_rfc3339();

        Ok(())
    }

    /// Get key metadata by ID.
    pub fn get_key_metadata(&self, key_id: &str) -> Option<HsmKeyMetadata> {
        self.keys.get(key_id).map(|(m, _)| m.clone())
    }

    /// List all key metadata.
    pub fn list_keys(&self) -> Vec<HsmKeyMetadata> {
        self.keys.values().map(|(m, _)| m.clone()).collect()
    }

    /// Export encrypted HSM keys using the Master Key.
    pub fn export_encrypted_keys(&self) -> Result<(String, String)> {
        let mk = self.ensure_initialized()?;
        let entries: Vec<ExportedKeyEntry> = self
            .keys
            .values()
            .map(|(m, k)| ExportedKeyEntry {
                metadata: m.clone(),
                raw_key_bytes: k.as_bytes().to_vec(),
            })
            .collect();

        let serialized = serde_json::to_vec(&entries)?;
        let (ciphertext, nonce) = encrypt_aes_gcm(mk, &SecretBuffer::from_slice(&serialized), b"HECATE_HSM_STATE")?;

        Ok((hex::encode(ciphertext), hex::encode(nonce)))
    }

    /// Import encrypted HSM keys using the Master Key.
    pub fn import_encrypted_keys(&mut self, ciphertext_hex: &str, nonce_hex: &str) -> Result<()> {
        let mk = self.ensure_initialized()?;
        let ciphertext = hex::decode(ciphertext_hex)?;
        let nonce = hex::decode(nonce_hex)?;

        let decrypted = decrypt_aes_gcm(mk, &nonce, &ciphertext, b"HECATE_HSM_STATE")?;
        let entries: Vec<ExportedKeyEntry> = serde_json::from_slice(decrypted.as_bytes())?;

        for entry in entries {
            let key = SecretBuffer::from_slice(&entry.raw_key_bytes);
            self.keys.insert(entry.metadata.key_id.clone(), (entry.metadata, key));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_hsm_lifecycle() -> Result<()> {
        let mut hsm = SoftwareHsm::new();
        let master_key = generate_key_256();
        hsm.init(master_key.clone())?;

        // Generate KEK
        let kek_meta = hsm.generate_key("primary-kek", KeyType::Aes256Gcm, HashMap::new())?;
        assert_eq!(kek_meta.current_version, 1);

        // Wrap & Unwrap DEK
        let raw_dek = generate_key_256();
        let (wrapped_dek, nonce, version) = hsm.wrap_key(&kek_meta.key_id, &raw_dek)?;
        assert_eq!(version, 1);

        let unwrapped_dek = hsm.unwrap_key(&kek_meta.key_id, &wrapped_dek, &nonce)?;
        assert_eq!(raw_dek.as_bytes(), unwrapped_dek.as_bytes());

        // In-HSM Encrypt & Decrypt
        let plaintext = SecretBuffer::from_str("ConfidentialDocument123");
        let (ciphertext, enc_nonce, _) = hsm.encrypt(&kek_meta.key_id, &plaintext, b"aad_data")?;
        let decrypted = hsm.decrypt(&kek_meta.key_id, &ciphertext, &enc_nonce, b"aad_data")?;
        assert_eq!(plaintext.as_bytes(), decrypted.as_bytes());

        // Export and Import Test
        let (enc_hex, nonce_hex) = hsm.export_encrypted_keys()?;
        let mut new_hsm = SoftwareHsm::new();
        new_hsm.init(master_key)?;
        new_hsm.import_encrypted_keys(&enc_hex, &nonce_hex)?;
        assert_eq!(new_hsm.list_keys().len(), 1);

        // Rotate Key
        let new_version = hsm.rotate_key(&kek_meta.key_id)?;
        assert_eq!(new_version, 2);

        // Destroy Key
        hsm.destroy_key(&kek_meta.key_id)?;
        assert!(hsm.encrypt(&kek_meta.key_id, &plaintext, b"").is_err());

        Ok(())
    }

    #[test]
    fn test_uninitialized_hsm_rejects_operations() {
        let mut hsm = SoftwareHsm::new();
        // Generate key before init
        assert!(hsm.generate_key("kek-01", KeyType::Aes256Gcm, HashMap::new()).is_err());
        // Rotate before init
        assert!(hsm.rotate_key("non-existent").is_err());
        // Export before init
        assert!(hsm.export_encrypted_keys().is_err());
        // Encrypt before init
        let secret = SecretBuffer::from_str("data");
        assert!(hsm.encrypt("key-01", &secret, b"").is_err());
    }

    #[test]
    fn test_hsm_non_existent_key_operations() -> Result<()> {
        let mut hsm = SoftwareHsm::new();
        hsm.init(generate_key_256())?;

        let secret = SecretBuffer::from_str("payload");
        assert!(hsm.encrypt("fake-key-id", &secret, b"").is_err());
        assert!(hsm.rotate_key("fake-key-id").is_err());
        assert!(hsm.unwrap_key("fake-key-id", &[0u8; 32], &[0u8; 12]).is_err());
        assert!(hsm.destroy_key("fake-key-id").is_err());
        Ok(())
    }

    #[test]
    fn test_hsm_aad_mismatch_fails_decryption() -> Result<()> {
        let mut hsm = SoftwareHsm::new();
        hsm.init(generate_key_256())?;

        let kek = hsm.generate_key("kek-aad", KeyType::Aes256Gcm, HashMap::new())?;
        let plaintext = SecretBuffer::from_str("AuthenticatedPayload");
        let (ct, nonce, _) = hsm.encrypt(&kek.key_id, &plaintext, b"correct-aad")?;

        // Decrypt with wrong AAD must fail
        assert!(hsm.decrypt(&kek.key_id, &ct, &nonce, b"wrong-aad").is_err());
        // Decrypt with correct AAD must succeed
        let recovered = hsm.decrypt(&kek.key_id, &ct, &nonce, b"correct-aad")?;
        assert_eq!(plaintext.as_bytes(), recovered.as_bytes());
        Ok(())
    }
}
