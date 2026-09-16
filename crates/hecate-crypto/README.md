# 🔐 `hecate-crypto`

> **Cryptographic Core, Software HSM State Machine, and Envelope Encryption Engine for Hecate Vault.**

[![Crates.io](https://img.shields.io/crates/v/hecate-crypto.svg?logo=rust)](https://crates.io/crates/hecate-crypto)
[![Docs.rs](https://docs.rs/hecate-crypto/badge.svg)](https://docs.rs/hecate-crypto)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/luciano-sparti/hecate-vault)

`hecate-crypto` is the high-assurance cryptographic foundation powering [Hecate Vault](https://github.com/luciano-sparti/hecate-vault). It provides memory-locked key buffers, Shamir $(k, n)$ secret sharing, multi-version envelope key wrapping, and an isolated Software HSM engine.

---

## ✨ Features

- **3-Tier Envelope Encryption**: Master Key (MK) $\to$ Key Encryption Key (KEK) $\to$ Data Encryption Key (DEK) hierarchy using **AES-256-GCM**.
- **Software HSM State Machine (`SoftwareHsm`)**: Opaque key handles, non-exportable KEKs, in-memory key wrapping, and version rotation.
- **$M$-of-$N$ Shamir Multi-Party Custody**: Secret sharing over $GF(2^8)$ with irreducible polynomial $x^8 + x^4 + x^3 + x + 1$ (`0x11D`).
- **Memory Pinning & Instant Zeroization**: `SecretBuffer` pinned via POSIX `mlock` (preventing paging to swap) with `ZeroizeOnDrop`.
- **Argon2id Key Derivation**: High-memory and iteration cost parameters for Master Key passphrase hashing.
- **Asymmetric Governance**: **Ed25519** signature generation and verification for tamper-evident policy envelopes.

---

## 📦 Installation

Add `hecate-crypto` to your `Cargo.toml`:

```toml
[dependencies]
hecate-crypto = "0.2.1"
```

---

## 🚀 Quick Example

```rust
use hecate_crypto::hsm::SoftwareHsm;
use hecate_crypto::shamir::split_secret;
use hecate_crypto::buffer::SecretBuffer;

fn main() -> anyhow::Result<()> {
    // 1. Initialize Software HSM with a Master Key
    let mut hsm = SoftwareHsm::new();
    let master_key = SecretBuffer::from_slice(&[0x42u8; 32]);
    hsm.initialize_with_master_key(master_key)?;

    // 2. Generate and rotate Key Encryption Keys (KEKs)
    let key_id = hsm.create_key("database-kek")?;
    hsm.rotate_key(&key_id)?;

    // 3. Wrap a Data Encryption Key (DEK) inside the HSM boundary
    let raw_dek = vec![0x11u8; 32];
    let wrapped_envelope = hsm.wrap_key(&key_id, &raw_dek)?;

    // 4. Split Master Key into 3-of-5 Shamir recovery shares
    let shares = split_secret(&[0x42u8; 32], 5, 3)?;
    assert_eq!(shares.len(), 5);

    Ok(())
}
```

---

## 🔗 Links

- **Main Repository**: [github.com/luciano-sparti/hecate-vault](https://github.com/luciano-sparti/hecate-vault)
- **Documentation**: [docs.rs/hecate-crypto](https://docs.rs/hecate-crypto)
- **Report Issues**: [github.com/luciano-sparti/hecate-vault/issues](https://github.com/luciano-sparti/hecate-vault/issues)
