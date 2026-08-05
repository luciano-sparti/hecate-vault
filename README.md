# Hecate Vault (`hecate`)

> **Local-first, TPM-backed hardware-sealed secrets vault CLI written in Rust.**

## Mythological Origin
In ancient mythology, **Hecate** is honored as *Kleidouchos* ("The Key-Bearer" / Guardian of Thresholds) who holds the master keys to sacred and hidden chambers. 

**Hecate Vault** serves as the guardian threshold between plaintext in-memory subshells and hardware-sealed disk storage. It complements workflow process managers (like **FATES**) by protecting the sensitive secrets and credentials that processes execute with.

## One-Line Description
A high-assurance, local-first secret vault CLI in Rust featuring TPM 2.0 key sealing, envelope encryption, zero-leak subshell execution, and tamper-evident audit logging.

## Problem
Developers and DevOps engineers need to store API keys, certificates, and credentials securely, but cloud secret managers require network connectivity, external accounts, and recurring costs. Local alternatives are often unencrypted, lack hardware binding, or leak secrets to shell histories and process tables.

## Solution
A local-first Rust CLI (`hecate`) that:
- Stores secrets locally using authenticated envelope encryption (AES-256-GCM / XChaCha20-Poly1305 with Argon2id KDF).
- Binds Master Keys to **TPM 2.0** hardware or native OS Keyrings (Windows DPAPI, macOS Keychain, Linux Secret Service).
- Zeroes sensitive key memory using Rust's `zeroize` primitives.
- Provides `hecate exec -- <cmd>` for zero-leak, subshell secret injection into sub-processes.
- Maintains an append-only, tamper-evident hash-chained audit log ($\text{Hash}_n = H(\text{Hash}_{n-1} \parallel \text{Entry})$).

## Technical Stack
- **Language**: Rust
- **CLI Framework**: `clap` (derive parser) with `rich`/colored output
- **Cryptography**: `argon2` (KDF), `aes-gcm` / `chacha20poly1305` (AEAD)
- **Memory Security**: `zeroize` for memory scrubbing, `libc` / Windows API for page locking (`mlock` / `VirtualLock`)
- **Hardware & OS Key Binding**: `tpm2-tss-rs` / platform OS credential APIs

## Scope
- Encrypted local secret storage with TPM 2.0 hardware binding and OS fallbacks.
- Complete CLI (`init`, `unlock`, `lock`, `set`, `get`, `list`, `delete`, `rotate`, `audit`, `exec`).
- Subshell execution helper (`hecate exec`).
- Encrypted backups & recovery.
- Pre-commit hook to detect unencrypted secret commits against vault secret signatures.

## Out of Scope (Initial PoC)
- Multi-tenant enterprise SSO/SCIM
- Cloud sync / distributed consensus
- GUI / browser-based interface

