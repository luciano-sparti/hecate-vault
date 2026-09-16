use anyhow::{anyhow, Result};
use hecate_crypto::verify_signature_hex;
use hecate_protocol::policy::{GuardPointPolicy, SignedPolicyEnvelope};
use prost::Message;
use std::collections::HashMap;

pub struct PolicySynchronizer {
    core_signing_public_key_hex: String,
    last_sequence_number: u32,
    active_policies: HashMap<String, GuardPointPolicy>,
}

impl PolicySynchronizer {
    pub fn new(core_signing_public_key_hex: String) -> Self {
        Self {
            core_signing_public_key_hex,
            last_sequence_number: 0,
            active_policies: HashMap::new(),
        }
    }

    pub fn verify_and_apply_envelopes(
        &mut self,
        envelopes: &[SignedPolicyEnvelope],
    ) -> Result<Vec<GuardPointPolicy>> {
        let mut updated = Vec::new();

        for envelope in envelopes {
            let mut sign_message = envelope.policy_payload_bytes.clone();
            sign_message.extend_from_slice(&envelope.timestamp.to_be_bytes());
            sign_message.extend_from_slice(&envelope.sequence_number.to_be_bytes());

            let is_valid = verify_signature_hex(
                &self.core_signing_public_key_hex,
                &sign_message,
                &envelope.core_signature,
            )?;

            if !is_valid {
                return Err(anyhow!("Core policy envelope signature verification failed! Possible tamper attempt."));
            }

            if envelope.sequence_number <= self.last_sequence_number && self.last_sequence_number > 0 {
                return Err(anyhow!("Replay attack or stale policy envelope detected (sequence: {})", envelope.sequence_number));
            }

            self.last_sequence_number = envelope.sequence_number;

            let policy = GuardPointPolicy::decode(&envelope.policy_payload_bytes[..])?;
            self.active_policies.insert(policy.policy_id.clone(), policy.clone());
            updated.push(policy);
        }

        Ok(updated)
    }

    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        let serialized = serde_json::to_string_pretty(&self.active_policies)?;
        std::fs::write(path, serialized)?;
        Ok(())
    }

    pub fn load_from_file(&mut self, path: &std::path::Path) -> Result<()> {
        if path.exists() {
            let data = std::fs::read_to_string(path)?;
            self.active_policies = serde_json::from_str(&data)?;
        }
        Ok(())
    }

    pub fn get_policies(&self) -> Vec<GuardPointPolicy> {
        self.active_policies.values().cloned().collect()
    }

    pub fn get_policy_by_path(&self, path: &str) -> Option<&GuardPointPolicy> {
        self.active_policies.values().find(|p| p.target_path == path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hecate_crypto::PolicySigner;
    use tempfile::tempdir;

    #[test]
    fn test_policy_synchronizer_lifecycle_and_security() -> Result<()> {
        let signer = PolicySigner::generate();
        let pub_hex = hex::encode(signer.verifying_key().to_bytes());
        let mut sync_engine = PolicySynchronizer::new(pub_hex);

        let policy = GuardPointPolicy {
            policy_id: "gp-01".to_string(),
            policy_name: "TestGuard".to_string(),
            target_path: "/mnt/test".to_string(),
            backing_path: "/mnt/backing".to_string(),
            key_id: "key-1".to_string(),
            deny_root_unauthorized: true,
            rules: vec![],
            policy_version: 1,
            updated_at: 1700000000,
        };

        let mut payload_bytes = Vec::new();
        policy.encode(&mut payload_bytes)?;

        let timestamp = chrono::Utc::now().timestamp();
        let seq: u32 = 1;

        let mut sign_message = payload_bytes.clone();
        sign_message.extend_from_slice(&timestamp.to_be_bytes());
        sign_message.extend_from_slice(&seq.to_be_bytes());
        let core_signature = signer.sign(&sign_message);

        let envelope = SignedPolicyEnvelope {
            policy_payload_bytes: payload_bytes,
            core_signature,
            timestamp,
            sequence_number: seq,
        };

        // 1. Valid envelope applied
        let applied = sync_engine.verify_and_apply_envelopes(&[envelope.clone()])?;
        assert_eq!(applied.len(), 1);
        assert_eq!(sync_engine.get_policies().len(), 1);
        assert!(sync_engine.get_policy_by_path("/mnt/test").is_some());

        // 2. Replay attack rejection (same sequence number)
        assert!(sync_engine.verify_and_apply_envelopes(&[envelope.clone()]).is_err());

        // 3. Tampered payload rejection
        let mut tampered_envelope = envelope.clone();
        tampered_envelope.sequence_number = 2;
        tampered_envelope.policy_payload_bytes[0] ^= 0xFF;
        assert!(sync_engine.verify_and_apply_envelopes(&[tampered_envelope]).is_err());

        // 4. Persistence roundtrip
        let dir = tempdir()?;
        let policy_file = dir.path().join("policies.json");
        sync_engine.save_to_file(&policy_file)?;

        let mut fresh_engine = PolicySynchronizer::new("fake_hex".to_string());
        fresh_engine.load_from_file(&policy_file)?;
        assert_eq!(fresh_engine.get_policies().len(), 1);
        assert_eq!(fresh_engine.get_policies()[0].policy_id, "gp-01");

        Ok(())
    }
}
