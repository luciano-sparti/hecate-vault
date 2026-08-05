pub mod envelope;

use anyhow::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A memory-locked, zeroizing buffer for sensitive secret bytes (keys, passphrases, ciphertexts).
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretBuffer {
    data: Vec<u8>,
}

impl SecretBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn from_str(s: &str) -> Self {
        Self {
            data: s.as_bytes().to_vec(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.data)
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl From<Vec<u8>> for SecretBuffer {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}
