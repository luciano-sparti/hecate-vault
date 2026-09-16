pub mod buffer;
pub mod envelope;
pub mod hsm;
pub mod kdf;
pub mod shamir;
pub mod signing;
pub mod tpm;

pub use buffer::SecretBuffer;
pub use envelope::{
    decrypt_aes_gcm, encrypt_aes_gcm, generate_key_256, generate_nonce_96, unwrap_key, wrap_key,
    EncryptedEnvelope,
};
pub use hsm::{HsmKeyMetadata, KeyState, KeyType, SoftwareHsm};
pub use kdf::{derive_key_argon2id, generate_salt};
pub use shamir::{combine_shares, split_secret, ShamirShare};
pub use signing::{verify_signature, verify_signature_hex, PolicySigner};
pub use tpm::{detect_root_trust, RootTrustProvider};
