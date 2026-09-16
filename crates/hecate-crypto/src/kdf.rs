use crate::buffer::SecretBuffer;
use anyhow::{anyhow, Result};
use argon2::{Argon2, Params};
use rand::{thread_rng, RngCore};

pub const KEY_SIZE_256: usize = 32; // 256 bits

/// Derive a 256-bit key from a passphrase using Argon2id with memory-hard parameters.
pub fn derive_key_argon2id(passphrase: &SecretBuffer, salt: &[u8]) -> Result<SecretBuffer> {
    let mut derived_key = [0u8; KEY_SIZE_256];
    
    // Argon2id parameters: 64MB memory, 3 iterations, 4 parallelism
    let params = Params::new(64 * 1024, 3, 4, Some(KEY_SIZE_256))
        .map_err(|e| anyhow!("Failed to configure Argon2 parameters: {}", e))?;
    
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_derivation() -> Result<()> {
        let pass = SecretBuffer::from_str("correct horse battery staple");
        let salt = generate_salt();
        let key1 = derive_key_argon2id(&pass, &salt)?;
        let key2 = derive_key_argon2id(&pass, &salt)?;
        assert_eq!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(key1.len(), 32);
        Ok(())
    }
}
