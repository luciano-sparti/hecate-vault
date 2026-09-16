use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub index: u64,
    pub timestamp: String,
    pub action: String,
    pub actor: String,
    pub details: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

impl AuditEntry {
    pub fn compute_hash(
        index: u64,
        timestamp: &str,
        action: &str,
        actor: &str,
        details: &str,
        prev_hash: &str,
    ) -> String {
        let payload = format!(
            "{}:{}:{}:{}:{}:{}",
            index, timestamp, action, actor, details, prev_hash
        );
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn new(index: u64, action: &str, actor: &str, details: &str, prev_hash: &str) -> Self {
        let timestamp = Utc::now().to_rfc3339();
        let entry_hash = Self::compute_hash(index, &timestamp, action, actor, details, prev_hash);
        Self {
            index,
            timestamp,
            action: action.to_string(),
            actor: actor.to_string(),
            details: details.to_string(),
            prev_hash: prev_hash.to_string(),
            entry_hash,
        }
    }
}

pub struct AuditLedger {
    file_path: PathBuf,
    entries: Vec<AuditEntry>,
}

impl AuditLedger {
    pub fn open_or_create(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut entries = Vec::new();
        if path.exists() {
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line_str = line?;
                if !line_str.trim().is_empty() {
                    let entry: AuditEntry = serde_json::from_str(&line_str)?;
                    entries.push(entry);
                }
            }
        }

        let ledger = Self {
            file_path: path.to_path_buf(),
            entries,
        };
        ledger.verify_chain()?;
        Ok(ledger)
    }

    pub fn reload(&mut self) -> Result<()> {
        let mut entries = Vec::new();
        if self.file_path.exists() {
            let file = File::open(&self.file_path)?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line_str = line?;
                if !line_str.trim().is_empty() {
                    let entry: AuditEntry = serde_json::from_str(&line_str)?;
                    entries.push(entry);
                }
            }
        }
        self.entries = entries;
        Ok(())
    }

    pub fn append(&mut self, action: &str, actor: &str, details: &str) -> Result<AuditEntry> {
        let _ = self.reload();
        let index = self.entries.len() as u64 + 1;
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| "0".repeat(64));

        let entry = AuditEntry::new(index, action, actor, details, &prev_hash);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)?;

        let serialized = serde_json::to_string(&entry)?;
        writeln!(file, "{}", serialized)?;
        self.entries.push(entry.clone());

        Ok(entry)
    }

    pub fn verify_chain(&self) -> Result<bool> {
        let mut expected_prev_hash = "0".repeat(64);
        for entry in &self.entries {
            if entry.prev_hash != expected_prev_hash {
                return Err(anyhow!(
                    "Audit ledger chain broken at index {}: expected prev_hash {}, found {}",
                    entry.index,
                    expected_prev_hash,
                    entry.prev_hash
                ));
            }
            let recalculated = AuditEntry::compute_hash(
                entry.index,
                &entry.timestamp,
                &entry.action,
                &entry.actor,
                &entry.details,
                &entry.prev_hash,
            );
            if recalculated != entry.entry_hash {
                return Err(anyhow!(
                    "Audit ledger hash tamper detected at index {}: expected {}, recalculated {}",
                    entry.index,
                    entry.entry_hash,
                    recalculated
                ));
            }
            expected_prev_hash = entry.entry_hash.clone();
        }
        Ok(true)
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_audit_ledger_append_and_verify() -> Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("audit.log");

        let mut ledger = AuditLedger::open_or_create(&path)?;
        ledger.append("INIT", "admin", "Initialized Software HSM")?;
        ledger.append("CREATE_KEY", "admin", "Created KEK key-01")?;
        ledger.append("ENROLL_AGENT", "node-01", "Agent node-01 enrolled")?;

        assert_eq!(ledger.entries().len(), 3);
        assert!(ledger.verify_chain()?);

        // Re-open from disk
        let reopened = AuditLedger::open_or_create(&path)?;
        assert_eq!(reopened.entries().len(), 3);
        assert!(reopened.verify_chain()?);

        Ok(())
    }
}
