# 🛡️ `hecate-agent`

> **Endpoint Enforcement Daemon and Transparent Guard Point Path Encryption Engine for Hecate Vault.**

[![Crates.io](https://img.shields.io/crates/v/hecate-agent.svg?logo=rust)](https://crates.io/crates/hecate-agent)
[![Docs.rs](https://docs.rs/hecate-agent/badge.svg)](https://docs.rs/hecate-agent)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/luciano-sparti/hecate-vault)

`hecate-agent` is the lightweight endpoint enforcement daemon of [Hecate Vault](https://github.com/luciano-sparti/hecate-vault). It establishes mutual TLS (mTLS) with `hecate-core`, verifies incoming policy bundles against the Core's asymmetric **Ed25519** public key, and enforces transparent file-level envelope encryption with strict process access controls.

---

## ✨ Key Capabilities

- **Transparent Guard Point Access**: Intercepts and validates file access according to active security policies.
- **Process Context Authorization**: Rejects unauthorized access with UID/GID matching, binary digest verification (`/proc/<pid>/exe`), and `deny_root_unauthorized` enforcement.
- **Offline Policy Resilience**: Locally caches cryptographic policies so file encryption and decryption function even during network interruptions.
- **Zero Core Runtime Requirement on Agent Host**: Does not require `hecate-core` to be installed on the agent host.

---

## 📦 Installation

Install the agent daemon directly from crates.io:

```bash
cargo install hecate-agent
```

---

## 🚀 Quick Usage

```bash
# 1. Enroll Agent with Hecate Core using a One-Time Enrollment Token (OTET)
hecate-agent enroll --token <OTET_TOKEN> --core http://127.0.0.1:50051

# 2. Check local Agent health and cached Guard Points
hecate-agent status

# 3. Protect a plaintext file into a Hecate Guarded envelope
hecate-agent protect --source data.csv --dest data.csv.enc --key-id <KEY_ID> --passphrase "secret"

# 4. Decrypt verified ciphertext envelope
hecate-agent unprotect --source data.csv.enc --dest restored.csv --passphrase "secret"

# 5. Execute a command within authorized Guard Point path context
hecate-agent exec --path /tmp/secure_mount /usr/bin/cat /tmp/secure_mount/data.csv

# 6. Run the continuous compliance and policy sync background daemon
hecate-agent run
```

---

## 🔗 Links

- **Main Repository**: [github.com/luciano-sparti/hecate-vault](https://github.com/luciano-sparti/hecate-vault)
- **Documentation**: [docs.rs/hecate-agent](https://docs.rs/hecate-agent)
- **Report Issues**: [github.com/luciano-sparti/hecate-vault/issues](https://github.com/luciano-sparti/hecate-vault/issues)
