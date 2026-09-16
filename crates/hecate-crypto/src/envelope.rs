use crate::buffer::SecretBuffer;
use anyhow::{anyhow, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};

pub const KEY_SIZE_256: usize = 32; // 256 bits
pub const NONCE_SIZE_96: usize = 12; // 96 bits standard GCM nonce

/// Encrypted envelope payload holding Base64/Hex serialized ciphertext and cryptographic nonce.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedEnvelope {
    pub salt_hex: Option<String>,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub key_version: u32,
}

/// Generate a cryptographically secure random 256-bit key.
pub fn generate_key_256() -> SecretBuffer {
    let mut key = [0u8; KEY_SIZE_256];
    thread_rng().fill_bytes(&mut key);
    SecretBuffer::new(key.to_vec())
}

/// Generate a random standard AEAD nonce (12 bytes).
pub fn generate_nonce_96() -> Vec<u8> {
    let mut nonce = [0u8; NONCE_SIZE_96];
    thread_rng().fill_bytes(&mut nonce);
    nonce.to_vec()
}

/// Encrypt data using AES-256-GCM with optional Additional Authenticated Data (AAD).
pub fn encrypt_aes_gcm(
    key: &SecretBuffer,
    plaintext: &SecretBuffer,
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    if key.len() != KEY_SIZE_256 {
        return Err(anyhow!("Invalid key length for AES-256-GCM: expected 32 bytes, got {}", key.len()));
    }

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| anyhow!("Failed to initialize AES-256-GCM cipher: {}", e))?;
    
    let nonce_bytes = generate_nonce_96();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext.as_bytes(),
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| anyhow!("AES-256-GCM encryption failed: {}", e))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt data using AES-256-GCM with optional Additional Authenticated Data (AAD).
pub fn decrypt_aes_gcm(
    key: &SecretBuffer,
    nonce_bytes: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<SecretBuffer> {
    if key.len() != KEY_SIZE_256 {
        return Err(anyhow!("Invalid key length for AES-256-GCM: expected 32 bytes, got {}", key.len()));
    }
    if nonce_bytes.len() != NONCE_SIZE_96 {
        return Err(anyhow!("Invalid nonce length: expected 12 bytes, got {}", nonce_bytes.len()));
    }

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| anyhow!("Failed to initialize AES-256-GCM cipher: {}", e))?;

    let nonce = Nonce::from_slice(nonce_bytes);

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| anyhow!("Decryption failed: integrity verification tag mismatch or corrupted ciphertext"))?;

    Ok(SecretBuffer::new(plaintext))
}

/// Wrap a Data Encryption Key (DEK) using a Key Encryption Key (KEK).
pub fn wrap_key(kek: &SecretBuffer, dek_to_wrap: &SecretBuffer) -> Result<(Vec<u8>, Vec<u8>)> {
    encrypt_aes_gcm(kek, dek_to_wrap, b"HECATE_KEY_WRAP_V1")
}

/// Unwrap a Data Encryption Key (DEK) using a Key Encryption Key (KEK).
pub fn unwrap_key(kek: &SecretBuffer, wrapped_dek: &[u8], nonce: &[u8]) -> Result<SecretBuffer> {
    decrypt_aes_gcm(kek, nonce, wrapped_dek, b"HECATE_KEY_WRAP_V1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_aes_gcm() -> Result<()> {
        let key = generate_key_256();
        let secret = SecretBuffer::from_str("SuperSecretDataPayload12345");
        let aad = b"context_metadata_test";

        let (ciphertext, nonce) = encrypt_aes_gcm(&key, &secret, aad)?;
        let decrypted = decrypt_aes_gcm(&key, &nonce, &ciphertext, aad)?;

        assert_eq!(secret.as_bytes(), decrypted.as_bytes());
        Ok(())
    }

    #[test]
    fn test_wrap_unwrap_key_cycle() -> Result<()> {
        let kek = generate_key_256();
        let dek = generate_key_256();

        let (wrapped_dek, nonce) = wrap_key(&kek, &dek)?;
        let unwrapped_dek = unwrap_key(&kek, &wrapped_dek, &nonce)?;

        assert_eq!(dek.as_bytes(), unwrapped_dek.as_bytes());
        Ok(())
    }

    #[test]
    fn test_tamper_detection() -> Result<()> {
        let key = generate_key_256();
        let secret = SecretBuffer::from_str("AuthenticData");
        let (mut ciphertext, nonce) = encrypt_aes_gcm(&key, &secret, b"")?;

        // Tamper with a single bit
        ciphertext[0] ^= 0x01;

        let result = decrypt_aes_gcm(&key, &nonce, &ciphertext, b"");
        assert!(result.is_err());
        Ok(())
    }
}
