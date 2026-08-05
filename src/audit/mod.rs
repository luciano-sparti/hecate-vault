use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};


#[derive(Debug, Clone, Serialize, Deserialize)]
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
        let payload = format!("{}:{}:{}:{}:{}:{}", index, timestamp, action, actor, details, prev_hash);
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn new(
        index: u64,
        action: &str,
        actor: &str,
        details: &str,
        prev_hash: &str,
    ) -> Self {
        let timestamp = chrono::Utc::now().to_rfc3339();
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
