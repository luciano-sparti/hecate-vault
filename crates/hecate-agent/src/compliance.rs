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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_compliance_auditor_posture_evaluation() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let target = dir.path().join("secure_mount");
        let backing = dir.path().join("backing_store");

        std::fs::create_dir_all(&target)?;
        std::fs::create_dir_all(&backing)?;

        let policy = GuardPointPolicy {
            policy_id: "gp-compliance".to_string(),
            policy_name: "AuditPolicy".to_string(),
            target_path: target.to_string_lossy().to_string(),
            backing_path: backing.to_string_lossy().to_string(),
            key_id: "key-comp".to_string(),
            deny_root_unauthorized: true,
            rules: vec![],
            policy_version: 1,
            updated_at: 0,
        };

        // 1. Fully compliant
        let report = ComplianceAuditor::audit_guard_point(&policy, 0);
        assert_eq!(report.status, "COMPLIANT");
        assert!(report.is_mounted);
        assert!(report.is_encrypted);

        // 2. Access violations trigger NON_COMPLIANT
        let violation_report = ComplianceAuditor::audit_guard_point(&policy, 5);
        assert_eq!(violation_report.status, "NON_COMPLIANT");
        assert_eq!(violation_report.access_violations_count, 5);

        // 3. Missing path triggers NON_COMPLIANT
        let mut missing_policy = policy.clone();
        missing_policy.target_path = "/non/existent/path/on/system".to_string();
        let missing_report = ComplianceAuditor::audit_guard_point(&missing_policy, 0);
        assert_eq!(missing_report.status, "NON_COMPLIANT");

        Ok(())
    }
}
