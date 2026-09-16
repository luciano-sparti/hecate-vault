pub mod hsm {
    tonic::include_proto!("hecate.hsm");
}

pub mod policy {
    tonic::include_proto!("hecate.policy");
}

pub mod agent {
    tonic::include_proto!("hecate.agent");
}

pub mod admin {
    tonic::include_proto!("hecate.admin");
}

pub use admin::*;
pub use agent::*;
pub use hsm::*;
pub use policy::*;

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn test_guard_point_policy_protobuf_roundtrip() {
        let policy = policy::GuardPointPolicy {
            policy_id: "gp-test-101".to_string(),
            policy_name: "Test Policy".to_string(),
            target_path: "/mnt/secure".to_string(),
            backing_path: "/mnt/backing".to_string(),
            key_id: "key-999".to_string(),
            deny_root_unauthorized: true,
            rules: vec![policy::PolicyRule {
                rule_id: "rule-1".to_string(),
                subjects: vec![policy::PolicySubject {
                    subject_type: policy::SubjectType::Uid as i32,
                    identifier: "1000".to_string(),
                }],
                action: policy::PermissionAction::ActionReadWrite as i32,
                allow: true,
            }],
            policy_version: 1,
            updated_at: 1700000000,
        };

        let mut buf = Vec::new();
        policy.encode(&mut buf).expect("encoding failed");
        let decoded = policy::GuardPointPolicy::decode(&buf[..]).expect("decoding failed");

        assert_eq!(policy.policy_id, decoded.policy_id);
        assert_eq!(policy.policy_name, decoded.policy_name);
        assert_eq!(policy.target_path, decoded.target_path);
        assert_eq!(policy.rules.len(), decoded.rules.len());
        assert_eq!(policy.deny_root_unauthorized, decoded.deny_root_unauthorized);
    }

    #[test]
    fn test_signed_policy_envelope_roundtrip() {
        let envelope = policy::SignedPolicyEnvelope {
            policy_payload_bytes: vec![1, 2, 3, 4, 5],
            core_signature: vec![0xAA; 64],
            sequence_number: 42,
            timestamp: 1700000000,
        };

        let mut buf = Vec::new();
        envelope.encode(&mut buf).expect("encoding failed");
        let decoded = policy::SignedPolicyEnvelope::decode(&buf[..]).expect("decoding failed");

        assert_eq!(envelope.sequence_number, decoded.sequence_number);
        assert_eq!(envelope.policy_payload_bytes, decoded.policy_payload_bytes);
        assert_eq!(envelope.core_signature, decoded.core_signature);
    }

    #[test]
    fn test_enroll_request_roundtrip() {
        let req = agent::EnrollRequest {
            one_time_token: "otet-abcdef123456".to_string(),
            hostname: "node-cluster-01".to_string(),
            os_info: "Linux 6.6.0-x86_64".to_string(),
            client_csr: "-----BEGIN CERTIFICATE REQUEST-----\n...".to_string(),
        };

        let mut buf = Vec::new();
        req.encode(&mut buf).expect("encoding failed");
        let decoded = agent::EnrollRequest::decode(&buf[..]).expect("decoding failed");

        assert_eq!(req.one_time_token, decoded.one_time_token);
        assert_eq!(req.hostname, decoded.hostname);
        assert_eq!(req.os_info, decoded.os_info);
        assert_eq!(req.client_csr, decoded.client_csr);
    }
}
