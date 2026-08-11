# Hecate Vault (`hecate`) — Project Plan

## Current status
- Concept, cryptographic architecture, and Rust project plan documented.
- Project named **Hecate Vault** (*Hecate Kleidouchos* — The Key-Bearer & Threshold Guardian), designed as the security vault counterpart to process managers like **FATES**.

## Goals
- Build a high-performance, local-first secret vault CLI in **Rust** with TPM 2.0 key sealing.
- Enforce cryptographically sound envelope encryption, in-memory zeroization (`zeroize`), and tamper-evident auditability.
- Prioritize security correctness, zero-leak execution UX (`hecate exec`), and practical DevOps workflow integration.

---

## Technical & Cryptographic Architecture Decisions
- **Language & Runtime**: **Rust** (static binary compilation, memory safety, explicit zeroization).
- **CLI Engine**: `clap` (v4 with derive API).
- **Cryptographic Primitives**:
  - Key Derivation Function (KDF): `argon2` crate (Argon2id memory-hard key derivation).
  - Authenticated Encryption (AEAD): `aes-gcm` or `chacha20poly1305` with random 192-bit nonces.
- **Envelope Encryption Model**:
  - **Master Key (MK)**: Protected by TPM 2.0 sealing (`tpm2-tss-rs`), OS Keyring (`keyring` crate / DPAPI / Keychain), or Argon2id passphrase.
  - **Data Encryption Keys (DEK)**: Unique key per secret or secret namespace, wrapped by the Master Key for instant rotation and re-keying.
- **In-Memory Security**:
  - Memory zeroization (`zeroize::Zeroize` / `ZeroizeOnDrop`) immediately after cryptographic operations.
  - Page locking (`mlock` / `VirtualLock`) to prevent plaintext secrets or keys from writing to disk swap files.
- **Hardware Sealing & OS Fallbacks**:
  - **TPM 2.0**: Primary hardware root of trust with optional PCR policy binding (e.g., PCR 0/7 integrity).
  - **OS Fallbacks**: Windows DPAPI/CNG, macOS Keychain, Linux Secret Service/Keyring.
- **Storage & Concurrency**:
  - Atomic write-rename file updates (`tempfile` -> final vault file) to prevent storage corruption.
  - File locking (`fd-lock` / `fs2`) for multi-process CLI safety.
- **Audit Ledger**:
  - Append-only hash chain ($\text{Hash}_n = \text{SHA-256}(\text{Hash}_{n-1} \parallel \text{Entry})$) for tamper-evident activity logging.

---

## Phase 1 — Repo Scaffold & Cargo Workspace Architecture
- Initialize Rust project with `Cargo.toml` (`hecate-vault` crate / binary `hecate`).
- Set up modular crate structure:
  - `src/main.rs` — CLI entrypoint and dispatch.
  - `src/cli/` — Command definitions (`clap` derive structs) and output formatting.
  - `src/vault/` — Secret models, schema serialization (`serde`), namespace handling.
  - `src/crypto/` — Argon2id KDF, AEAD engines, envelope key hierarchy, and `zeroize` buffers.
  - `src/storage/` — Atomic file writers, storage serialization, and file locking.
  - `src/tpm/` — TPM 2.0 hardware binding and native OS keyring fallbacks.
  - `src/audit/` — Append-only hash-chained audit ledger.
  - `src/exec/` — Subprocess spawning and ephemeral environment injection.

## Phase 2 — Core Vault Model & Envelope Encryption
- Define secret schema: metadata, DEK-encrypted payload ciphertext, versioning, timestamps, tags.
- Implement Master Key derivation and lifecycle (`init`, `unlock`, `lock`).
- Add memory-locked buffer management (`zeroize`) and secure key destruction routines.

## Phase 3 — Hardware Sealing & Native OS Fallbacks
- Implement TPM 2.0 detection and key sealing protocol.
- Implement native platform fallbacks:
  - Windows DPAPI / CNG.
  - macOS Keychain.
  - Linux Secret Service API / Kernel Keyring.
- Document threat model differences between hardware-sealed and OS-bound states.

## Phase 4 — CLI Commands & Safe Secret Execution (`hecate exec`)
- Core commands:
  - Life cycle: `hecate init`, `hecate unlock`, `hecate lock`, `hecate status`
  - Secrets management: `hecate set`, `hecate get`, `hecate list`, `hecate delete`, `hecate rotate`
  - Backup & Inspection: `hecate import`, `hecate export`, `hecate audit`
- Implement **`hecate exec -- <command>`** for ephemeral, subshell secret injection without leaking values to shell history or environment files.

## Phase 5 — Access Policies & Hash-Chained Audit Ledger
- Path-based and namespace access policy rules.
- Append-only hash-chained audit logging to detect log tampering or entry deletion.

## Phase 6 — Integration & CI/DevOps Tooling
- Non-interactive unlock workflow for headless CI/CD environments.
- Kubernetes secret injector wrapper.
- Pre-commit git hook to detect unencrypted secrets in source code by comparing against vault secret signatures.

## Phase 7 — Safety Controls, Recovery & Hardening
- Destructive action confirmations and safety prompts.
- Encrypted passphrase-wrapped backup and recovery workflows.
- Deterministic test suite, snapshot testing, and zeroization verification.

## Phase 8 — Packaging & Security Review
- Static binary compilation (`cargo build --release`).
- Comprehensive threat model review, edge-case audit, and operational documentation.

---

## Completion Criteria
- Vault securely stores, retrieves, rotates, and executes commands with encrypted secrets via `hecate`.
- Envelope encryption and memory zeroization ensure cryptographic safety in transit and at rest.
- TPM 2.0 key sealing functions on supported platforms with seamless, documented OS key store fallbacks.
- `hecate exec` safely injects secrets into sub-processes without disk or shell history leakage.
- README and documentation clearly detail threat model, security boundaries, and operational best practices.

---

- **Root‑of‑Trust Detection**: Ensure `detect_root_trust` checks TPM / OS keyring without leaving test entries and handles headless WSL environments gracefully.
- **Audit & Crypto Coverage**: Plan to integrate `AuditEntry` usage and expose AEAD utilities via the vault API in later phases.
