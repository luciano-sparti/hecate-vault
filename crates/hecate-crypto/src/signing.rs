use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

/// An Ed25519 keypair for signing Core policy envelopes and attestation tokens.
#[derive(Debug, Clone)]
pub struct PolicySigner {
    signing_key: SigningKey,
}

impl PolicySigner {
    /// Generate a new random Ed25519 signing key.
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self { signing_key }
    }

    /// Load from 32-byte secret key slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(anyhow!("Invalid Ed25519 signing key length: expected 32 bytes"));
        }
        let array: [u8; 32] = bytes.try_into()?;
        let signing_key = SigningKey::from_bytes(&array);
        Ok(Self { signing_key })
    }

    /// Export secret key bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get corresponding verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get verifying key in hex format.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key().to_bytes())
    }

    /// Sign a payload slice (e.g. serialized policy envelope).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(message);
        signature.to_vec()
    }
}

/// Verify an Ed25519 signature against a public key and message.
pub fn verify_signature(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> Result<bool> {
    if public_key_bytes.len() != 32 {
        return Err(anyhow!("Invalid Ed25519 public key length: expected 32 bytes"));
    }
    if signature_bytes.len() != 64 {
        return Err(anyhow!("Invalid Ed25519 signature length: expected 64 bytes"));
    }

    let pub_array: [u8; 32] = public_key_bytes.try_into()?;
    let verifying_key = VerifyingKey::from_bytes(&pub_array)
        .map_err(|e| anyhow!("Invalid Ed25519 public key format: {}", e))?;

    let sig_array: [u8; 64] = signature_bytes.try_into()?;
    let signature = Signature::from_bytes(&sig_array);

    match verifying_key.verify(message, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify an Ed25519 signature using a hex-encoded public key.
pub fn verify_signature_hex(public_key_hex: &str, message: &[u8], signature_bytes: &[u8]) -> Result<bool> {
    let pub_bytes = hex::decode(public_key_hex).map_err(|e| anyhow!("Invalid hex public key: {}", e))?;
    verify_signature(&pub_bytes, message, signature_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_and_verify_cycle() -> Result<()> {
        let signer = PolicySigner::generate();
        let payload = b"GuardPointPolicy: /data/secure, UID=1000, GID=1000, SEQ=1";

        let sig = signer.sign(payload);
        let pub_bytes = signer.verifying_key().to_bytes();

        let is_valid = verify_signature(&pub_bytes, payload, &sig)?;
        assert!(is_valid);

        let is_invalid = verify_signature(&pub_bytes, b"TamperedPayload", &sig)?;
        assert!(!is_invalid);

        Ok(())
    }
}
