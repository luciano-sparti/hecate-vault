# 📡 `hecate-protocol`

> **Protobuf Schemas, gRPC Contracts, and Shared Network Wire Types for Hecate Vault.**

[![Crates.io](https://img.shields.io/crates/v/hecate-protocol.svg?logo=rust)](https://crates.io/crates/hecate-protocol)
[![Docs.rs](https://docs.rs/hecate-protocol/badge.svg)](https://docs.rs/hecate-protocol)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/luciano-sparti/hecate-vault)

`hecate-protocol` contains the compiled Protocol Buffers schemas, Tonic gRPC service contracts, and strongly-typed wire models powering communication between `hecate-core` and distributed `hecate-agent` nodes.

---

## 📋 Included Protocol Contracts

- **`hsm.proto`**: HSM remote key operations (`WrapKey`, `UnwrapKey`, `RotateKey`, `GetMasterKeyStatus`).
- **`policy.proto`**: Dynamic Guard Point policies, Ed25519-signed policy bundles, and monotonic revision counters.
- **`agent.proto`**: One-Time Enrollment Token (OTET) registration, mTLS certificate exchange, and telemetry heartbeats.
- **`admin.proto`**: Audit ledger streaming, Shamir $(k, n)$ disaster recovery unsealing, and compliance posture queries.

---

## 📦 Installation

Add `hecate-protocol` to your `Cargo.toml`:

```toml
[dependencies]
hecate-protocol = "0.2.1"
```

---

## 🔗 Links

- **Main Repository**: [github.com/luciano-sparti/hecate-vault](https://github.com/luciano-sparti/hecate-vault)
- **Documentation**: [docs.rs/hecate-protocol](https://docs.rs/hecate-protocol)
- **Report Issues**: [github.com/luciano-sparti/hecate-vault/issues](https://github.com/luciano-sparti/hecate-vault/issues)
