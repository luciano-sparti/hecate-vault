use keyring::Entry;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RootTrustProvider {
    Tpm2,
    OsKeyring,
    PassphraseOnly,
}

impl std::fmt::Display for RootTrustProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RootTrustProvider::Tpm2 => write!(f, "TPM 2.0 Hardware Sealing"),
            RootTrustProvider::OsKeyring => write!(f, "Native OS Keyring"),
            RootTrustProvider::PassphraseOnly => write!(f, "Argon2id Passphrase"),
        }
    }
}

/// Detects available root-of-trust hardware or OS key sealing services.
pub fn detect_root_trust() -> RootTrustProvider {
    #[cfg(target_os = "linux")]
    if std::path::Path::new("/dev/tpmrm0").exists() || std::path::Path::new("/dev/tpm0").exists() {
        return RootTrustProvider::Tpm2;
    }

    if Entry::new("hecate_vault_healthcheck", "test").is_ok() {
        return RootTrustProvider::OsKeyring;
    }

    RootTrustProvider::PassphraseOnly
}
