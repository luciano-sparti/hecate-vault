use anyhow::{anyhow, Context, Result};
use hecate_crypto::{
    decrypt_aes_gcm, derive_key_argon2id, encrypt_aes_gcm, generate_salt, SecretBuffer,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisasterRecoveryArchive {
    pub version: String,
    pub created_at: String,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub encrypted_payload_hex: String,
    pub payload_sha256: String,
}

/// Create an encrypted Disaster Recovery archive containing all vault database, policy, and audit state.
pub fn create_dr_backup(
    data_payload: &[u8],
    passphrase: &SecretBuffer,
) -> Result<(Vec<u8>, String)> {
    let salt = generate_salt();
    let key = derive_key_argon2id(passphrase, &salt)?;

    let mut hasher = Sha256::new();
    hasher.update(data_payload);
    let payload_sha256 = hex::encode(hasher.finalize());

    let (ciphertext, nonce) = encrypt_aes_gcm(&key, &SecretBuffer::from_slice(data_payload), b"HECATE_DR_BACKUP")?;

    let archive = DisasterRecoveryArchive {
        version: "2.0.0".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        encrypted_payload_hex: hex::encode(ciphertext),
        payload_sha256: payload_sha256.clone(),
    };

    let serialized = serde_json::to_vec_pretty(&archive)?;
    Ok((serialized, payload_sha256))
}

/// Restore and decrypt a Disaster Recovery archive.
pub fn restore_dr_backup(
    archive_bytes: &[u8],
    passphrase: &SecretBuffer,
) -> Result<Vec<u8>> {
    let archive: DisasterRecoveryArchive = serde_json::from_slice(archive_bytes)
        .context("Invalid disaster recovery archive format")?;

    let salt = hex::decode(&archive.salt_hex)?;
    let nonce = hex::decode(&archive.nonce_hex)?;
    let ciphertext = hex::decode(&archive.encrypted_payload_hex)?;

    let key = derive_key_argon2id(passphrase, &salt)?;
    let decrypted = decrypt_aes_gcm(&key, &nonce, &ciphertext, b"HECATE_DR_BACKUP")?;

    let mut hasher = Sha256::new();
    hasher.update(decrypted.as_bytes());
    let recalculated_sha256 = hex::encode(hasher.finalize());

    if recalculated_sha256 != archive.payload_sha256 {
        return Err(anyhow!("Disaster recovery archive integrity verification failed"));
    }

    Ok(decrypted.as_bytes().to_vec())
}
