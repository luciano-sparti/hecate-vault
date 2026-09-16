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

    pub fn get_policies(&self) -> Vec<GuardPointPolicy> {
        self.active_policies.values().cloned().collect()
    }

    pub fn get_policy_by_path(&self, path: &str) -> Option<&GuardPointPolicy> {
        self.active_policies.values().find(|p| p.target_path == path)
    }
}
