use hecate_protocol::agent::GuardPointCompliance;
use hecate_protocol::policy::GuardPointPolicy;
use std::path::Path;

pub struct ComplianceAuditor;

impl ComplianceAuditor {
    pub fn audit_guard_point(
        policy: &GuardPointPolicy,
        violations_count: u64,
    ) -> GuardPointCompliance {
        let target_path = Path::new(&policy.target_path);
        let backing_path = Path::new(&policy.backing_path);

        let target_exists = target_path.exists();
        let backing_exists = backing_path.exists();

        let is_encrypted = backing_exists;
        let is_mounted = target_exists;

        let (status, error_message) = if !target_exists {
            ("NON_COMPLIANT".to_string(), "Target guard point path does not exist".to_string())
        } else if !backing_exists {
            ("NON_COMPLIANT".to_string(), "Backing encrypted store does not exist".to_string())
        } else if violations_count > 0 {
            ("NON_COMPLIANT".to_string(), format!("{} access violations detected", violations_count))
        } else {
            ("COMPLIANT".to_string(), "".to_string())
        };

        GuardPointCompliance {
            path: policy.target_path.clone(),
            is_mounted,
            is_encrypted,
            access_violations_count: violations_count,
            status,
            error_message,
        }
    }

    pub fn audit_all(
        policies: &[GuardPointPolicy],
        violations_map: &std::collections::HashMap<String, u64>,
    ) -> Vec<GuardPointCompliance> {
        policies
            .iter()
            .map(|p| {
                let count = violations_map.get(&p.policy_id).copied().unwrap_or(0);
                Self::audit_guard_point(p, count)
            })
            .collect()
    }
}
