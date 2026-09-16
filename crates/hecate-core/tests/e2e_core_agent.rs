use anyhow::Result;
use hecate_agent::client::AgentClient;
use hecate_agent::compliance::ComplianceAuditor;
use hecate_agent::guard::{Authorizer, FileGuard, ProcessContext};
use hecate_agent::sync::PolicySynchronizer;
use hecate_core::agents::AgentRegistry;
use hecate_core::audit::AuditLedger;
use hecate_core::ha::backup::{create_dr_backup, restore_dr_backup};
use hecate_core::pki::InternalCertificateAuthority;
use hecate_core::policy::PolicyStore;
use hecate_core::secrets::{VaultDatabase, VaultStorage};
use hecate_core::server::{CoreState, HecateCoreServer};
use hecate_crypto::{
    combine_shares, generate_key_256, generate_salt, split_secret, KeyType, PolicySigner,
    SecretBuffer, SoftwareHsm,
};
use hecate_protocol::admin::admin_service_server::AdminServiceServer;
use hecate_protocol::agent::agent_service_server::AgentServiceServer;
use hecate_protocol::hsm::hsm_crypto_service_server::HsmCryptoServiceServer;
use hecate_protocol::policy::{
    GuardPointPolicy, PermissionAction, PolicyRule, PolicySubject, SubjectType,
};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::RwLock;
use tonic::transport::Server;

#[tokio::test]
async fn test_full_lifecycle_core_and_agent_e2e() -> Result<()> {
    let temp_core_dir = tempdir()?;
    let core_base_dir = temp_core_dir.path().to_path_buf();

    // 1. Initialize Software HSM, Master Key, and Shamir 3-of-5 split
    let master_key = generate_key_256();
    let key_shares = split_secret(&master_key, 3, 5)?;
    assert_eq!(key_shares.len(), 5);

    // Verify Shamir recovery
    let recovered_mk = combine_shares(&key_shares[0..3])?;
    assert_eq!(master_key.as_bytes(), recovered_mk.as_bytes());

    let mut hsm = SoftwareHsm::new();
    hsm.init(master_key.clone())?;

    // Create KEK inside HSM
    let kek_meta = hsm.generate_key("primary-kek", KeyType::Aes256Gcm, HashMap::new())?;
    assert_eq!(kek_meta.current_version, 1);

    // 2. Setup Core Storage, PKI, Audit Ledger, Policy Store
    let vault_storage = VaultStorage::new(core_base_dir.join("vault.json"));
    let salt = generate_salt();
    let vault_db = VaultDatabase::new("e2e-vault", hex::encode(salt), "tpm2".to_string());
    vault_storage.save(&vault_db)?;

    let mut policy_store = PolicyStore::new();
    let policy_signer = PolicySigner::generate();
    let mut agent_registry = AgentRegistry::new();
    let mut audit_ledger = AuditLedger::open_or_create(&core_base_dir.join("audit.log"))?;
    audit_ledger.append("INIT_HSM", "admin", "Initialized HSM Master Key and KEK")?;

    let pki = InternalCertificateAuthority::generate_or_load(&core_base_dir.join("pki.json"))?;

    // Generate enrollment token on Core
    let enrollment_token = agent_registry.generate_token("test-agent-node", 3600);

    // Register a Guard Point Policy
    let test_guard_dir = tempdir()?;
    let target_path = test_guard_dir.path().join("secure_mount");
    let backing_path = test_guard_dir.path().join("backing_store");
    fs::create_dir_all(&target_path)?;
    fs::create_dir_all(&backing_path)?;

    let policy = GuardPointPolicy {
        policy_id: "gp-e2e-01".to_string(),
        policy_name: "prod-database-guard".to_string(),
        target_path: target_path.to_string_lossy().to_string(),
        backing_path: backing_path.to_string_lossy().to_string(),
        key_id: kek_meta.key_id.clone(),
        deny_root_unauthorized: true,
        rules: vec![PolicyRule {
            rule_id: "rule-allow-uid-1000".to_string(),
            subjects: vec![PolicySubject {
                subject_type: SubjectType::Uid as i32,
                identifier: "1000".to_string(),
            }],
            action: PermissionAction::ActionReadWrite as i32,
            allow: true,
        }],
        policy_version: 1,
        updated_at: chrono::Utc::now().timestamp(),
    };
    policy_store.add_or_update_policy(policy.clone());

    let core_state = Arc::new(RwLock::new(CoreState {
        hsm,
        vault_storage,
        vault_db,
        policy_store,
        policy_signer: policy_signer.clone(),
        agent_registry,
        audit_ledger,
        pki,
        base_dir: core_base_dir.clone(),
    }));
    core_state.write().await.persist()?;

    // 3. Start Core gRPC Server on ephemeral local port
    let local_addr: SocketAddr = "127.0.0.1:50124".parse()?;
    let server_core = HecateCoreServer::new(core_state.clone());

    tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(AdminServiceServer::new(server_core.clone()))
            .add_service(AgentServiceServer::new(server_core.clone()))
            .add_service(HsmCryptoServiceServer::new(server_core))
            .serve(local_addr)
            .await;
    });

    // Give server a moment to bind
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let core_url = format!("http://{}", local_addr);

    // 4. Agent Enrolls with Core
    let mut agent_client = AgentClient::connect(core_url).await?;
    let enroll_res = agent_client
        .enroll(
            enrollment_token.token,
            "test-agent-node".to_string(),
            "linux".to_string(),
        )
        .await?;

    assert_eq!(enroll_res.core_signing_public_key, policy_signer.public_key_hex());
    assert!(!enroll_res.agent_id.is_empty());

    // 5. Agent Synchronizes Policies from Core & Verifies Ed25519 Signature
    let mut policy_sync = PolicySynchronizer::new(enroll_res.core_signing_public_key);
    let sync_res = agent_client
        .sync_policies(enroll_res.agent_id.clone(), 0)
        .await?;

    let verified_policies = policy_sync.verify_and_apply_envelopes(&sync_res.signed_policies)?;
    assert_eq!(verified_policies.len(), 1);
    assert_eq!(verified_policies[0].policy_id, "gp-e2e-01");

    // 6. Test File Encryption at Guard Point
    let plain_file = target_path.join("sensitive_data.txt");
    let enc_file = backing_path.join("sensitive_data.enc");
    let restored_file = target_path.join("restored_data.txt");

    fs::write(&plain_file, b"TOP_SECRET_ENTERPRISE_DATABASE_PAYLOAD_12345")?;
    let dek = generate_key_256();

    FileGuard::encrypt_file(&plain_file, &enc_file, &kek_meta.key_id, &dek)?;
    assert!(enc_file.exists());

    FileGuard::decrypt_file(&enc_file, &restored_file, &dek)?;
    let restored_content = fs::read(&restored_file)?;
    assert_eq!(restored_content, b"TOP_SECRET_ENTERPRISE_DATABASE_PAYLOAD_12345");

    // 7. Verify Process Credential Authorizer
    let auth_ctx = ProcessContext {
        pid: 100,
        uid: 1000,
        gid: 1000,
        binary_path: "/usr/bin/app".to_string(),
        binary_sha256: "abc".to_string(),
    };
    let (authorized, _) = Authorizer::is_authorized(&policy, &auth_ctx, PermissionAction::ActionRead);
    assert!(authorized, "UID 1000 should be authorized");

    let unauth_ctx = ProcessContext {
        pid: 101,
        uid: 1001,
        gid: 1001,
        binary_path: "/usr/bin/unauth".to_string(),
        binary_sha256: "xyz".to_string(),
    };
    let (denied, _) = Authorizer::is_authorized(&policy, &unauth_ctx, PermissionAction::ActionRead);
    assert!(!denied, "UID 1001 should be denied");

    let root_unauth_ctx = ProcessContext {
        pid: 102,
        uid: 0,
        gid: 0,
        binary_path: "/bin/bash".to_string(),
        binary_sha256: "root_hash".to_string(),
    };
    let (root_denied, reason) = Authorizer::is_authorized(&policy, &root_unauth_ctx, PermissionAction::ActionRead);
    assert!(!root_denied, "Root without explicit rule must be denied by deny_root_unauthorized");
    assert!(reason.unwrap().contains("deny_root_unauthorized"));

    // 8. Agent Audits Compliance and Reports to Core
    let compliance_items = ComplianceAuditor::audit_all(&verified_policies, &HashMap::new());
    assert_eq!(compliance_items.len(), 1);
    assert_eq!(compliance_items[0].status, "COMPLIANT");

    let comp_res = agent_client
        .report_compliance(enroll_res.agent_id.clone(), compliance_items)
        .await?;
    assert!(comp_res.recorded);

    // 9. Verify Core Audit Ledger Chain Integrity
    let state_guard = core_state.read().await;
    assert!(state_guard.audit_ledger.verify_chain()?);
    assert!(state_guard.audit_ledger.entries().len() >= 2);

    // 10. Test Disaster Recovery Backup & Restore
    let db_payload = serde_json::to_vec(&state_guard.vault_db)?;
    let dr_pass = SecretBuffer::from_str("disaster_recovery_secure_password_test");
    let (dr_archive, sha256) = create_dr_backup(&db_payload, &dr_pass)?;
    assert!(!sha256.is_empty());

    let restored_db_bytes = restore_dr_backup(&dr_archive, &dr_pass)?;
    assert_eq!(db_payload, restored_db_bytes);

    Ok(())
}
