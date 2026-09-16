# 🏛️ `hecate-core`

> **Software HSM Authority, mTLS Policy Management Plane, and Interactive Terminal UI for Hecate Vault.**

[![Crates.io](https://img.shields.io/crates/v/hecate-core.svg?logo=rust)](https://crates.io/crates/hecate-core)
[![Docs.rs](https://docs.rs/hecate-core/badge.svg)](https://docs.rs/hecate-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/luciano-sparti/hecate-vault)

`hecate-core` is the central security authority and management plane of [Hecate Vault](https://github.com/luciano-sparti/hecate-vault). It provides an isolated **Software Hardware Security Module (Soft-HSM)**, internal X.509 PKI, asymmetric policy signing, Shamir $(k, n)$ multi-custody recovery, and a built-in **Ratatui Terminal UI**.

---

## ✨ Key Capabilities

- **Software HSM Engine**: Isolated non-exportable Master Keys and Key Encryption Keys (KEKs).
- **gRPC + mTLS Management Server**: Zero-trust certificate authentication and dynamic policy synchronization.
- **Asymmetric Policy Signing**: Signs policy updates with Ed25519 before broadcasting to endpoint agents.
- **M-of-N Shamir Disaster Recovery**: Split Master Keys across 3-of-5 custodians; unseal or backup via `.hct` encrypted archives.
- **Tamper-Evident SHA-256 Audit Ledger**: Cryptographically hash-chained immutable audit log.
- **Full Interactive TUI (`hecate-tui`)**: 6-view terminal dashboard built with Ratatui and Crossterm.

---

## 📦 Installation

Install both the Core daemon and the standalone TUI directly from crates.io:

```bash
cargo install hecate-core
```

---

## 🚀 Quick Usage

```bash
# 1. Initialize Core with 3-of-5 Shamir custody
hecate-core init --shares 5 --threshold 3 --passphrase "secret"

# 2. Launch the Interactive Terminal UI
hecate-tui

# 3. Create a Key Encryption Key (KEK)
hecate-core key create --alias prod-db-kek --key-type aes256gcm

# 4. Define a Guard Point policy
hecate-core policy add \
  --id gp-db \
  --name "Production DB" \
  --target-path /data/db \
  --backing-path /data/db.enc \
  --key-id <KEY_ID> \
  --deny-root

# 5. Start the gRPC Management Server
hecate-core server --listen 127.0.0.1:50051 &

# 6. Mint an Agent Enrollment Token
hecate-core agent token --hostname node-prod-01 --validity-seconds 3600
```

---

## 🔗 Links

- **Main Repository**: [github.com/luciano-sparti/hecate-vault](https://github.com/luciano-sparti/hecate-vault)
- **Documentation**: [docs.rs/hecate-core](https://docs.rs/hecate-core)
- **Report Issues**: [github.com/luciano-sparti/hecate-vault/issues](https://github.com/luciano-sparti/hecate-vault/issues)
