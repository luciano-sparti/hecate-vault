use anyhow::Result;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A memory-locked, zeroizing buffer for sensitive secret bytes (keys, passphrases, ciphertexts).
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretBuffer {
    data: Vec<u8>,
}

impl SecretBuffer {
    /// Create a new SecretBuffer and attempt to lock its memory page using mlock.
    pub fn new(data: Vec<u8>) -> Self {
        #[cfg(unix)]
        {
            if !data.is_empty() {
                unsafe {
                    libc::mlock(data.as_ptr() as *const libc::c_void, data.len());
                }
            }
        }
        Self { data }
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }

    pub fn from_str(s: &str) -> Self {
        Self::new(s.as_bytes().to_vec())
    }

    pub fn empty() -> Self {
        Self { data: Vec::new() }
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

impl fmt::Debug for SecretBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuffer([REDACTED: {} bytes])", self.data.len())
    }
}

impl From<Vec<u8>> for SecretBuffer {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for SecretBuffer {
    fn from(slice: &[u8]) -> Self {
        Self::from_slice(slice)
    }
}

impl From<&str> for SecretBuffer {
    fn from(s: &str) -> Self {
        Self::from_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_buffer_creation_and_redaction() {
        let buf = SecretBuffer::from_str("my_secret_token");
        assert_eq!(buf.as_bytes(), b"my_secret_token");
        assert_eq!(buf.as_str().unwrap(), "my_secret_token");
        assert_eq!(format!("{:?}", buf), "SecretBuffer([REDACTED: 15 bytes])");
    }
}
