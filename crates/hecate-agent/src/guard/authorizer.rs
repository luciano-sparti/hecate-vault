use anyhow::Result;
use hecate_protocol::policy::{GuardPointPolicy, PermissionAction, SubjectType};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;

#[derive(Debug, Clone)]
pub struct ProcessContext {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub binary_path: String,
    pub binary_sha256: String,
}

impl ProcessContext {
    pub fn current() -> Self {
        #[cfg(unix)]
        let (pid, uid, gid) = unsafe {
            (
                libc::getpid() as u32,
                libc::getuid() as u32,
                libc::getgid() as u32,
            )
        };
        #[cfg(not(unix))]
        let (pid, uid, gid) = (0, 1000, 1000);

        let binary_path = std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let binary_sha256 = Self::hash_file(&binary_path).unwrap_or_default();

        Self {
            pid,
            uid,
            gid,
            binary_path,
            binary_sha256,
        }
    }

    pub fn hash_file(path: &str) -> Result<String> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        Ok(hex::encode(hasher.finalize()))
    }
}

pub struct Authorizer;

impl Authorizer {
    pub fn is_authorized(
        policy: &GuardPointPolicy,
        ctx: &ProcessContext,
        _action: PermissionAction,
    ) -> (bool, Option<String>) {
        // Root containment check
        if ctx.uid == 0 && policy.deny_root_unauthorized {
            let matches_root_rule = policy.rules.iter().any(|rule| {
                rule.subjects.iter().any(|s| {
                    (s.subject_type() == SubjectType::Uid && s.identifier == "0")
                        || (s.subject_type() == SubjectType::BinaryHash && s.identifier.eq_ignore_ascii_case(&ctx.binary_sha256))
                }) && rule.allow
            });

            if !matches_root_rule {
                return (false, Some("Root access denied by deny_root_unauthorized policy".to_string()));
            }
        }

        // Evaluate rules
        for rule in &policy.rules {
            for subject in &rule.subjects {
                let subject_match = match subject.subject_type() {
                    SubjectType::Uid => subject.identifier == ctx.uid.to_string(),
                    SubjectType::Gid => subject.identifier == ctx.gid.to_string(),
                    SubjectType::BinaryHash => subject.identifier.eq_ignore_ascii_case(&ctx.binary_sha256),
                    SubjectType::User => true,
                    _ => false,
                };

                if subject_match {
                    if rule.allow {
                        return (true, None);
                    } else {
                        return (false, Some(format!("Explicitly denied by rule {}", rule.rule_id)));
                    }
                }
            }
        }

        (false, Some("No matching authorization rule found for process context".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hecate_protocol::policy::PolicyRule;

    #[test]
    fn test_authorizer_rules() {
        let policy = GuardPointPolicy {
            policy_id: "gp-01".to_string(),
            policy_name: "prod".to_string(),
            target_path: "/data/secure".to_string(),
            backing_path: "/var/lib/hecate/backing".to_string(),
            key_id: "key-01".to_string(),
            deny_root_unauthorized: true,
            rules: vec![PolicyRule {
                rule_id: "rule-1000".to_string(),
                subjects: vec![hecate_protocol::policy::PolicySubject {
                    subject_type: SubjectType::Uid as i32,
                    identifier: "1000".to_string(),
                }],
                action: PermissionAction::ActionReadWrite as i32,
                allow: true,
            }],
            policy_version: 1,
            updated_at: 0,
        };

        let authorized_ctx = ProcessContext {
            pid: 123,
            uid: 1000,
            gid: 1000,
            binary_path: "/usr/bin/app".to_string(),
            binary_sha256: "abc".to_string(),
        };

        let (allowed, _) = Authorizer::is_authorized(&policy, &authorized_ctx, PermissionAction::ActionRead);
        assert!(allowed);

        let unauthorized_ctx = ProcessContext {
            pid: 124,
            uid: 1001,
            gid: 1001,
            binary_path: "/usr/bin/hacker".to_string(),
            binary_sha256: "xyz".to_string(),
        };

        let (denied, _) = Authorizer::is_authorized(&policy, &unauthorized_ctx, PermissionAction::ActionRead);
        assert!(!denied);
    }

    #[test]
    fn test_root_containment_deny_root_unauthorized() {
        let policy = GuardPointPolicy {
            policy_id: "gp-root-secure".to_string(),
            policy_name: "Root Guarded Path".to_string(),
            target_path: "/root/vault".to_string(),
            backing_path: "/root/vault_backing".to_string(),
            key_id: "key-root".to_string(),
            deny_root_unauthorized: true,
            rules: vec![PolicyRule {
                rule_id: "rule-app".to_string(),
                subjects: vec![hecate_protocol::policy::PolicySubject {
                    subject_type: SubjectType::Uid as i32,
                    identifier: "1000".to_string(),
                }],
                action: PermissionAction::ActionReadWrite as i32,
                allow: true,
            }],
            policy_version: 1,
            updated_at: 0,
        };

        // Root process without explicit rule must be rejected
        let root_ctx = ProcessContext {
            pid: 1,
            uid: 0,
            gid: 0,
            binary_path: "/usr/bin/cat".to_string(),
            binary_sha256: "deadbeef".to_string(),
        };

        let (allowed, reason) = Authorizer::is_authorized(&policy, &root_ctx, PermissionAction::ActionRead);
        assert!(!allowed);
        assert!(reason.unwrap().contains("Root access denied"));
    }

    #[test]
    fn test_binary_hash_authorization() {
        let trusted_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let policy = GuardPointPolicy {
            policy_id: "gp-hash-guard".to_string(),
            policy_name: "Hash Guard".to_string(),
            target_path: "/data/proc".to_string(),
            backing_path: "/data/proc_backing".to_string(),
            key_id: "key-hash".to_string(),
            deny_root_unauthorized: false,
            rules: vec![PolicyRule {
                rule_id: "rule-hash".to_string(),
                subjects: vec![hecate_protocol::policy::PolicySubject {
                    subject_type: SubjectType::BinaryHash as i32,
                    identifier: trusted_hash.to_string(),
                }],
                action: PermissionAction::ActionReadWrite as i32,
                allow: true,
            }],
            policy_version: 1,
            updated_at: 0,
        };

        let valid_binary_ctx = ProcessContext {
            pid: 500,
            uid: 1000,
            gid: 1000,
            binary_path: "/usr/local/bin/trusted_app".to_string(),
            binary_sha256: trusted_hash.to_string(),
        };
        assert!(Authorizer::is_authorized(&policy, &valid_binary_ctx, PermissionAction::ActionRead).0);

        let untrusted_binary_ctx = ProcessContext {
            pid: 501,
            uid: 1000,
            gid: 1000,
            binary_path: "/usr/local/bin/untrusted_app".to_string(),
            binary_sha256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        };
        assert!(!Authorizer::is_authorized(&policy, &untrusted_binary_ctx, PermissionAction::ActionRead).0);
    }
}
