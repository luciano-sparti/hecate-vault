use crate::crypto::SecretBuffer;
use anyhow::{anyhow, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Params};

use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};

const KEY_SIZE: usize = 32; // 256 bits for AES-256
const NONCE_SIZE: usize = 12; // 96 bits standard GCM nonce

/// Encrypted envelope payload holding ciphertext, salt, and nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// Derive a 256-bit key from a passphrase using Argon2id.
pub fn derive_key(passphrase: &SecretBuffer, salt: &[u8]) -> Result<SecretBuffer> {
    let mut derived_key = [0u8; KEY_SIZE];
    
    // Argon2id with strong default parameters (64MB memory, 3 iterations, 4 parallelism)
    let params = Params::new(64 * 1024, 3, 4, Some(KEY_SIZE))
        .map_err(|e| anyhow!("Failed to configure Argon2 params: {}", e))?;
    
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut derived_key)
        .map_err(|e| anyhow!("Argon2 key derivation failed: {}", e))?;

    Ok(SecretBuffer::new(derived_key.to_vec()))
}

/// Generate a cryptographically secure random salt (16 bytes).
pub fn generate_salt() -> Vec<u8> {
    let mut salt = [0u8; 16];
    thread_rng().fill_bytes(&mut salt);
    salt.to_vec()
}

/// Generate a random AEAD nonce (12 bytes).
pub fn generate_nonce() -> Vec<u8> {
    let mut nonce = [0u8; NONCE_SIZE];
    thread_rng().fill_bytes(&mut nonce);
    nonce.to_vec()
}

/// Encrypt data using AES-256-GCM with a secret key.
pub fn encrypt_aes_gcm(key: &SecretBuffer, plaintext: &SecretBuffer) -> Result<(Vec<u8>, Vec<u8>)> {
    if key.len() != KEY_SIZE {
        return Err(anyhow!("Invalid key length for AES-256-GCM: expected 32 bytes"));
    }

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| anyhow!("Failed to initialize AES-256-GCM cipher: {}", e))?;
    
    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow!("AES-256-GCM encryption failed: {}", e))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt data using AES-256-GCM with a secret key and nonce.
pub fn decrypt_aes_gcm(key: &SecretBuffer, nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<SecretBuffer> {
    if key.len() != KEY_SIZE {
        return Err(anyhow!("Invalid key length for AES-256-GCM: expected 32 bytes"));
    }
    if nonce_bytes.len() != NONCE_SIZE {
        return Err(anyhow!("Invalid nonce length: expected 12 bytes"));
    }

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| anyhow!("Failed to initialize AES-256-GCM cipher: {}", e))?;

    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("Decryption failed: invalid key, tampered ciphertext, or corrupted nonce"))?;

    Ok(SecretBuffer::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_cycle() -> Result<()> {
        let passphrase = SecretBuffer::from_str("master_super_secret_passphrase");
        let salt = generate_salt();
        let key = derive_key(&passphrase, &salt)?;

        let secret_payload = SecretBuffer::from_str("API_KEY_LIVE_987654321");
        let (ciphertext, nonce) = encrypt_aes_gcm(&key, &secret_payload)?;

        let decrypted = decrypt_aes_gcm(&key, &nonce, &ciphertext)?;
        assert_eq!(secret_payload.as_bytes(), decrypted.as_bytes());
        Ok(())
    }
}
