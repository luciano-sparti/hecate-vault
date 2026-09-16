use anyhow::{anyhow, Result};
use hecate_crypto::{
    decrypt_aes_gcm, derive_key_argon2id, encrypt_aes_gcm, generate_salt, SecretBuffer,
};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedFileHeader {
    pub magic: String,
    pub version: u32,
    pub key_id: String,
    pub salt_hex: String,
    pub nonce_hex: String,
}

pub struct FileGuard;

impl FileGuard {
    const MAGIC: &'static str = "HECATE_GUARD_V2";

    pub fn encrypt_file(
        source_path: &Path,
        dest_path: &Path,
        key_id: &str,
        passphrase: &SecretBuffer,
    ) -> Result<()> {
        let mut source_file = File::open(source_path)?;
        let mut plaintext = Vec::new();
        source_file.read_to_end(&mut plaintext)?;

        let salt = generate_salt();
        let dek = derive_key_argon2id(passphrase, &salt)?;

        let (ciphertext, nonce) = encrypt_aes_gcm(&dek, &SecretBuffer::from_slice(&plaintext), b"HECATE_FILE_GUARD")?;

        let header = EncryptedFileHeader {
            magic: Self::MAGIC.to_string(),
            version: 2,
            key_id: key_id.to_string(),
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce),
        };

        let header_json = serde_json::to_vec(&header)?;
        let header_len = (header_json.len() as u32).to_be_bytes();

        let mut dest_file = File::create(dest_path)?;
        dest_file.write_all(&header_len)?;
        dest_file.write_all(&header_json)?;
        dest_file.write_all(&ciphertext)?;
        dest_file.flush()?;

        Ok(())
    }

    pub fn decrypt_file(
        source_path: &Path,
        dest_path: &Path,
        passphrase: &SecretBuffer,
    ) -> Result<()> {
        let mut file = File::open(source_path)?;
        let mut len_bytes = [0u8; 4];
        file.read_exact(&mut len_bytes)?;
        let header_len = u32::from_be_bytes(len_bytes) as usize;

        let mut header_json = vec![0u8; header_len];
        file.read_exact(&mut header_json)?;

        let header: EncryptedFileHeader = serde_json::from_slice(&header_json)?;
        if header.magic != Self::MAGIC {
            return Err(anyhow!("Invalid file format or corrupted Hecate guard header"));
        }

        let salt = hex::decode(&header.salt_hex)?;
        let nonce = hex::decode(&header.nonce_hex)?;
        let mut ciphertext = Vec::new();
        file.read_to_end(&mut ciphertext)?;

        let dek = derive_key_argon2id(passphrase, &salt)?;
        let plaintext = decrypt_aes_gcm(&dek, &nonce, &ciphertext, b"HECATE_FILE_GUARD")?;

        let mut dest_file = File::create(dest_path)?;
        dest_file.write_all(plaintext.as_bytes())?;
        dest_file.flush()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_file_guard_encrypt_and_decrypt_cycle() -> Result<()> {
        let dir = tempdir()?;
        let src = dir.path().join("plaintext.txt");
        let enc = dir.path().join("ciphertext.enc");
        let restored = dir.path().join("restored.txt");

        let original_data = b"DatabaseCredentials,SecretKeys,API_TOKENS_2026";
        fs::write(&src, original_data)?;

        let passphrase = SecretBuffer::from_str("AgentGuardPassphrase123!");

        // 1. Encrypt
        FileGuard::encrypt_file(&src, &enc, "kek-prod-db", &passphrase)?;
        assert!(enc.exists());

        // 2. Decrypt
        FileGuard::decrypt_file(&enc, &restored, &passphrase)?;
        let decrypted_bytes = fs::read(&restored)?;
        assert_eq!(original_data.as_slice(), decrypted_bytes.as_slice());

        // 3. Wrong passphrase fails
        let wrong_passphrase = SecretBuffer::from_str("WrongPassphrase!");
        let wrong_dest = dir.path().join("wrong.txt");
        assert!(FileGuard::decrypt_file(&enc, &wrong_dest, &wrong_passphrase).is_err());

        // 4. Corrupted file fails
        let corrupt_file = dir.path().join("corrupt.enc");
        fs::write(&corrupt_file, b"NOT_A_VALID_HEADER")?;
        assert!(FileGuard::decrypt_file(&corrupt_file, &wrong_dest, &passphrase).is_err());

        Ok(())
    }
}
