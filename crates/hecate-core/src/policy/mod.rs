use anyhow::Result;
use chrono::Utc;
use hecate_crypto::PolicySigner;
use hecate_protocol::policy::{GuardPointPolicy, SignedPolicyEnvelope};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use tempfile::NamedTempFile;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStore {
    policies: HashMap<String, GuardPointPolicy>,
    sequence_number: u32,
}

impl PolicyStore {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            sequence_number: 0,
        }
    }

    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let mut file = File::open(path)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            let store: PolicyStore = serde_json::from_str(&contents)?;
            Ok(store)
        } else {
            Ok(Self::new())
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let serialized = serde_json::to_vec_pretty(self)?;
        let mut temp_file = NamedTempFile::new_in(path.parent().unwrap_or(Path::new(".")))?;
        temp_file.write_all(&serialized)?;
        temp_file.flush()?;
        temp_file.persist(path)?;
        Ok(())
    }

    pub fn add_or_update_policy(&mut self, mut policy: GuardPointPolicy) -> String {
        self.sequence_number += 1;
        policy.policy_version += 1;
        policy.updated_at = Utc::now().timestamp();
        let id = policy.policy_id.clone();
        self.policies.insert(id.clone(), policy);
        id
    }

    pub fn list_policies(&self) -> Vec<GuardPointPolicy> {
        self.policies.values().cloned().collect()
    }

    pub fn get_policy(&self, id: &str) -> Option<&GuardPointPolicy> {
        self.policies.get(id)
    }

    pub fn get_policy_mut(&mut self, id: &str) -> Option<&mut GuardPointPolicy> {
        self.policies.get_mut(id)
    }

    pub fn remove_policy(&mut self, id: &str) -> bool {
        self.policies.remove(id).is_some()
    }

    pub fn sign_policies(&mut self, signer: &PolicySigner) -> Result<Vec<SignedPolicyEnvelope>> {
        let mut envelopes = Vec::new();
        for policy in self.policies.values() {
            let mut payload_bytes = Vec::new();
            policy.encode(&mut payload_bytes)?;

            self.sequence_number += 1;
            let timestamp = Utc::now().timestamp();

            let mut sign_message = payload_bytes.clone();
            sign_message.extend_from_slice(&timestamp.to_be_bytes());
            sign_message.extend_from_slice(&self.sequence_number.to_be_bytes());

            let signature = signer.sign(&sign_message);

            envelopes.push(SignedPolicyEnvelope {
                policy_payload_bytes: payload_bytes,
                core_signature: signature,
                timestamp,
                sequence_number: self.sequence_number,
            });
        }
        Ok(envelopes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hecate_crypto::verify_signature;

    #[test]
    fn test_policy_store_crud_and_signing() -> Result<()> {
        let mut store = PolicyStore::new();
        let signer = PolicySigner::generate();

        let policy = GuardPointPolicy {
            policy_id: "gp-db-01".to_string(),
            policy_name: "Production DB Guard".to_string(),
            target_path: "/var/lib/db".to_string(),
            backing_path: "/var/lib/db.enc".to_string(),
            key_id: "key-123".to_string(),
            deny_root_unauthorized: true,
            rules: vec![],
            policy_version: 1,
            updated_at: 1700000000,
        };

        // 1. Add policy
        let id = store.add_or_update_policy(policy.clone());
        assert_eq!(id, "gp-db-01");
        assert_eq!(store.list_policies().len(), 1);

        // 2. Retrieve policy
        let fetched = store.get_policy("gp-db-01").unwrap();
        assert_eq!(fetched.policy_name, "Production DB Guard");

        // 3. Sign policy envelopes
        let envelopes = store.sign_policies(&signer)?;
        assert_eq!(envelopes.len(), 1);
        let env = &envelopes[0];
        assert_eq!(env.sequence_number, 2);

        // Verify signature
        let mut sign_message = env.policy_payload_bytes.clone();
        sign_message.extend_from_slice(&env.timestamp.to_be_bytes());
        sign_message.extend_from_slice(&env.sequence_number.to_be_bytes());
        let valid = verify_signature(&signer.verifying_key().to_bytes(), &sign_message, &env.core_signature)?;
        assert!(valid);

        // 4. Remove policy
        assert!(store.remove_policy("gp-db-01"));
        assert!(store.list_policies().is_empty());
        assert!(!store.remove_policy("gp-db-01"));

        Ok(())
    }
}
