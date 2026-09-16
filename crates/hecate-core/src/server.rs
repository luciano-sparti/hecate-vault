use crate::agents::AgentRegistry;
use crate::audit::AuditLedger;
use crate::ha::backup::{create_dr_backup, restore_dr_backup};
use crate::pki::InternalCertificateAuthority;
use crate::policy::PolicyStore;
use crate::secrets::{VaultDatabase, VaultStorage};
use anyhow::Result;
use hecate_crypto::{
    generate_key_256, KeyState, PolicySigner, SecretBuffer, SoftwareHsm,
};
use hecate_protocol::admin::admin_service_server::AdminService;
use hecate_protocol::admin::*;
use hecate_protocol::agent::agent_service_server::AgentService;
use hecate_protocol::agent::*;
use hecate_protocol::hsm::hsm_crypto_service_server::HsmCryptoService;
use hecate_protocol::hsm::*;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};

pub struct CoreState {
    pub hsm: SoftwareHsm,
    pub vault_storage: VaultStorage,
    pub vault_db: VaultDatabase,
    pub policy_store: PolicyStore,
    pub policy_signer: PolicySigner,
    pub agent_registry: AgentRegistry,
    pub audit_ledger: AuditLedger,
    pub pki: InternalCertificateAuthority,
    pub base_dir: PathBuf,
}

impl CoreState {
    pub fn persist(&mut self) -> Result<()> {
        if let Ok((enc_hex, nonce_hex)) = self.hsm.export_encrypted_keys() {
            self.vault_db.encrypted_hsm_state_hex = Some(enc_hex);
            self.vault_db.hsm_nonce_hex = Some(nonce_hex);
        }
        self.vault_storage.save(&self.vault_db)?;
        self.policy_store.save(&self.base_dir.join("policies.json"))?;
        self.agent_registry.save(&self.base_dir.join("agents.json"))?;
        Ok(())
    }

    pub fn reload_from_disk(&mut self) {
        let agents_path = self.base_dir.join("agents.json");
        if agents_path.exists() {
            if let Ok(reg) = AgentRegistry::load_or_create(&agents_path) {
                self.agent_registry = reg;
            }
        }
        let policies_path = self.base_dir.join("policies.json");
        if policies_path.exists() {
            if let Ok(store) = PolicyStore::load_or_create(&policies_path) {
                self.policy_store = store;
            }
        }
        let _ = self.audit_ledger.reload();
    }
}

#[derive(Clone)]
pub struct HecateCoreServer {
    state: Arc<RwLock<CoreState>>,
}

impl HecateCoreServer {
    pub fn new(state: Arc<RwLock<CoreState>>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl HsmCryptoService for HecateCoreServer {
    async fn generate_key(
        &self,
        request: Request<GenerateKeyRequest>,
    ) -> Result<Response<GenerateKeyResponse>, Status> {
        let req = request.into_inner();
        let mut state = self.state.write().await;

        let key_type = match req.key_type() {
            KeyType::Aes256Gcm => hecate_crypto::KeyType::Aes256Gcm,
            KeyType::Chacha20Poly1305 => hecate_crypto::KeyType::ChaCha20Poly1305,
            KeyType::HmacSha256 => hecate_crypto::KeyType::HmacSha256,
            KeyType::Unspecified => hecate_crypto::KeyType::Aes256Gcm,
        };

        let meta = state
            .hsm
            .generate_key(&req.key_alias, key_type, req.tags)
            .map_err(|e| Status::internal(e.to_string()))?;

        state
            .audit_ledger
            .append("GENERATE_KEY", "admin", &format!("Key ID: {}, Alias: {}", meta.key_id, meta.key_alias))
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = state.persist();

        Ok(Response::new(GenerateKeyResponse {
            key_id: meta.key_id,
            version: meta.current_version,
            state: KeyState::Active as i32,
        }))
    }

    async fn wrap_key(
        &self,
        request: Request<WrapKeyRequest>,
    ) -> Result<Response<WrapKeyResponse>, Status> {
        let req = request.into_inner();
        let state = self.state.read().await;

        let dek = SecretBuffer::from_slice(&req.dek_to_wrap);
        let (wrapped, nonce, kek_version) = state
            .hsm
            .wrap_key(&req.kek_id, &dek)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(WrapKeyResponse {
            wrapped_dek: wrapped,
            nonce,
            kek_version,
        }))
    }

    async fn unwrap_key(
        &self,
        request: Request<UnwrapKeyRequest>,
    ) -> Result<Response<UnwrapKeyResponse>, Status> {
        let req = request.into_inner();
        let state = self.state.read().await;

        let unwrapped = state
            .hsm
            .unwrap_key(&req.kek_id, &req.wrapped_dek, &req.nonce)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(UnwrapKeyResponse {
            unwrapped_dek: unwrapped.as_bytes().to_vec(),
        }))
    }

    async fn encrypt(
        &self,
        request: Request<EncryptRequest>,
    ) -> Result<Response<EncryptResponse>, Status> {
        let req = request.into_inner();
        let state = self.state.read().await;

        let (ciphertext, nonce, version) = state
            .hsm
            .encrypt(&req.key_id, &SecretBuffer::from_slice(&req.plaintext), &req.aad)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(EncryptResponse {
            ciphertext,
            nonce,
            tag: Vec::new(),
            key_version: version,
        }))
    }

    async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        let req = request.into_inner();
        let state = self.state.read().await;

        let decrypted = state
            .hsm
            .decrypt(&req.key_id, &req.ciphertext, &req.nonce, &req.aad)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(DecryptResponse {
            plaintext: decrypted.as_bytes().to_vec(),
        }))
    }

    async fn rotate_key(
        &self,
        request: Request<RotateKeyRequest>,
    ) -> Result<Response<RotateKeyResponse>, Status> {
        let req = request.into_inner();
        let mut state = self.state.write().await;

        let new_version = state
            .hsm
            .rotate_key(&req.key_id)
            .map_err(|e| Status::internal(e.to_string()))?;

        state
            .audit_ledger
            .append("ROTATE_KEY", "admin", &format!("Key ID: {}, New Version: {}", req.key_id, new_version))
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = state.persist();

        Ok(Response::new(RotateKeyResponse {
            key_id: req.key_id,
            new_version,
        }))
    }

    async fn get_key_info(
        &self,
        request: Request<GetKeyInfoRequest>,
    ) -> Result<Response<GetKeyInfoResponse>, Status> {
        let req = request.into_inner();
        let state = self.state.read().await;

        let meta = state
            .hsm
            .get_key_metadata(&req.key_id)
            .ok_or_else(|| Status::not_found(format!("Key '{}' not found", req.key_id)))?;

        Ok(Response::new(GetKeyInfoResponse {
            key_id: meta.key_id,
            key_alias: meta.key_alias,
            key_type: meta.key_type as i32,
            current_version: meta.current_version,
            state: meta.state as i32,
            created_at: 0,
            updated_at: 0,
        }))
    }

    async fn destroy_key(
        &self,
        request: Request<DestroyKeyRequest>,
    ) -> Result<Response<DestroyKeyResponse>, Status> {
        let req = request.into_inner();
        let mut state = self.state.write().await;

        state
            .hsm
            .destroy_key(&req.key_id)
            .map_err(|e| Status::internal(e.to_string()))?;

        state
            .audit_ledger
            .append("DESTROY_KEY", "admin", &format!("Key ID: {}", req.key_id))
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = state.persist();

        Ok(Response::new(DestroyKeyResponse {
            success: true,
            destroyed_at: chrono::Utc::now().timestamp(),
        }))
    }
}

#[tonic::async_trait]
impl AgentService for HecateCoreServer {
    async fn enroll_agent(
        &self,
        request: Request<EnrollRequest>,
    ) -> Result<Response<EnrollResponse>, Status> {
        let req = request.into_inner();
        let mut state = self.state.write().await;
        state.reload_from_disk();

        let agent_id = state
            .agent_registry
            .validate_and_consume_token(&req.one_time_token)
            .map_err(|e| Status::unauthenticated(e.to_string()))?;

        let (client_cert_pem, _, cert_expires_at) = state
            .pki
            .issue_client_certificate(&req.hostname, &agent_id)
            .map_err(|e| Status::internal(e.to_string()))?;

        state.agent_registry.register_agent(
            agent_id.clone(),
            req.hostname.clone(),
            req.os_info.clone(),
        );

        state
            .audit_ledger
            .append("ENROLL_AGENT", &agent_id, &format!("Agent enrolled: hostname={}", req.hostname))
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = state.persist();

        Ok(Response::new(EnrollResponse {
            agent_id,
            client_certificate_pem: client_cert_pem,
            ca_certificate_pem: state.pki.ca_cert_pem.clone(),
            core_signing_public_key: state.policy_signer.public_key_hex(),
            cert_expires_at,
        }))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let req = request.into_inner();
        let mut state = self.state.write().await;
        state.reload_from_disk();

        state
            .agent_registry
            .record_heartbeat(&req.agent_id)
            .map_err(|e| Status::unauthenticated(e.to_string()))?;

        Ok(Response::new(HeartbeatResponse {
            acknowledge: true,
            policy_update_available: false,
        }))
    }

    async fn sync_policies(
        &self,
        _request: Request<SyncPolicyRequest>,
    ) -> Result<Response<SyncPolicyResponse>, Status> {
        let mut state = self.state.write().await;
        state.reload_from_disk();
        let signer = state.policy_signer.clone();
        let envelopes = state
            .policy_store
            .sign_policies(&signer)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(SyncPolicyResponse {
            signed_policies: envelopes,
            latest_policy_version: 1,
        }))
    }

    async fn report_compliance(
        &self,
        request: Request<ComplianceReportRequest>,
    ) -> Result<Response<ComplianceReportResponse>, Status> {
        let req = request.into_inner();
        let mut state = self.state.write().await;
        state.reload_from_disk();

        state
            .agent_registry
            .update_compliance(&req.agent_id, req.items)
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = state.persist();

        Ok(Response::new(ComplianceReportResponse { recorded: true }))
    }

    async fn fetch_guard_key(
        &self,
        request: Request<GuardKeyRequest>,
    ) -> Result<Response<GuardKeyResponse>, Status> {
        let req = request.into_inner();
        let state = self.state.read().await;

        let (wrapped, nonce, version) = state
            .hsm
            .wrap_key(&req.key_id, &generate_key_256())
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(GuardKeyResponse {
            wrapped_dek: wrapped,
            nonce,
            key_version: version,
        }))
    }
}

#[tonic::async_trait]
impl AdminService for HecateCoreServer {
    async fn generate_enrollment_token(
        &self,
        request: Request<GenerateTokenRequest>,
    ) -> Result<Response<GenerateTokenResponse>, Status> {
        let req = request.into_inner();
        let mut state = self.state.write().await;
        state.reload_from_disk();

        let token = state
            .agent_registry
            .generate_token(&req.agent_hostname, req.validity_seconds);

        state
            .audit_ledger
            .append("GENERATE_TOKEN", "admin", &format!("Token generated for {}", req.agent_hostname))
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = state.persist();

        Ok(Response::new(GenerateTokenResponse {
            token: token.token,
            expires_at: token.expires_at,
        }))
    }

    async fn list_agents(
        &self,
        _request: Request<ListAgentsRequest>,
    ) -> Result<Response<ListAgentsResponse>, Status> {
        let mut state = self.state.write().await;
        state.reload_from_disk();
        let agents = state.agent_registry.list_agents();
        Ok(Response::new(ListAgentsResponse { agents }))
    }

    async fn revoke_agent(
        &self,
        request: Request<RevokeAgentRequest>,
    ) -> Result<Response<RevokeAgentResponse>, Status> {
        let req = request.into_inner();
        let mut state = self.state.write().await;
        state.reload_from_disk();

        state
            .agent_registry
            .revoke_agent(&req.agent_id)
            .map_err(|e| Status::not_found(e.to_string()))?;

        state
            .audit_ledger
            .append("REVOKE_AGENT", "admin", &format!("Revoked agent {}: {}", req.agent_id, req.reason))
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = state.persist();

        Ok(Response::new(RevokeAgentResponse { success: true }))
    }

    async fn create_policy(
        &self,
        request: Request<CreatePolicyRequest>,
    ) -> Result<Response<CreatePolicyResponse>, Status> {
        let req = request.into_inner();
        let policy = req
            .policy
            .ok_or_else(|| Status::invalid_argument("Missing policy payload"))?;

        let mut state = self.state.write().await;
        state.reload_from_disk();
        let id = state.policy_store.add_or_update_policy(policy);

        state
            .audit_ledger
            .append("CREATE_POLICY", "admin", &format!("Created policy ID: {}", id))
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = state.persist();

        Ok(Response::new(CreatePolicyResponse { policy_id: id }))
    }

    async fn update_policy(
        &self,
        request: Request<UpdatePolicyRequest>,
    ) -> Result<Response<UpdatePolicyResponse>, Status> {
        let req = request.into_inner();
        let policy = req
            .policy
            .ok_or_else(|| Status::invalid_argument("Missing policy payload"))?;

        let mut state = self.state.write().await;
        state.reload_from_disk();
        state.policy_store.add_or_update_policy(policy);

        let _ = state.persist();

        Ok(Response::new(UpdatePolicyResponse {
            success: true,
            new_version: 2,
        }))
    }

    async fn list_policies(
        &self,
        _request: Request<ListPoliciesRequest>,
    ) -> Result<Response<ListPoliciesResponse>, Status> {
        let mut state = self.state.write().await;
        state.reload_from_disk();
        let policies = state.policy_store.list_policies();
        Ok(Response::new(ListPoliciesResponse { policies }))
    }

    async fn get_compliance_dashboard(
        &self,
        _request: Request<ComplianceDashboardRequest>,
    ) -> Result<Response<ComplianceDashboardResponse>, Status> {
        let mut state = self.state.write().await;
        state.reload_from_disk();
        let agents = state.agent_registry.list_agents();
        let total = agents.len() as u32;
        let compliant = agents.iter().filter(|a| a.compliance_status == "COMPLIANT").count() as u32;
        let non_compliant = total.saturating_sub(compliant);

        Ok(Response::new(ComplianceDashboardResponse {
            total_agents: total,
            compliant_agents: compliant,
            non_compliant_agents: non_compliant,
            agent_details: agents,
        }))
    }

    async fn export_audit_logs(
        &self,
        _request: Request<AuditExportRequest>,
    ) -> Result<Response<AuditExportResponse>, Status> {
        let state = self.state.read().await;
        let records = state
            .audit_ledger
            .entries()
            .iter()
            .map(|e| AuditRecord {
                index: e.index,
                timestamp: e.timestamp.clone(),
                action: e.action.clone(),
                actor: e.actor.clone(),
                details: e.details.clone(),
                prev_hash: e.prev_hash.clone(),
                entry_hash: e.entry_hash.clone(),
            })
            .collect();

        let chain_valid = state.audit_ledger.verify_chain().unwrap_or(false);

        Ok(Response::new(AuditExportResponse {
            records,
            chain_integrity_valid: chain_valid,
        }))
    }

    async fn create_backup(
        &self,
        request: Request<CreateBackupRequest>,
    ) -> Result<Response<CreateBackupResponse>, Status> {
        let req = request.into_inner();
        let state = self.state.read().await;

        let db_bytes = serde_json::to_vec(&state.vault_db)
            .map_err(|e| Status::internal(e.to_string()))?;

        let (archive, sha256) = create_dr_backup(&db_bytes, &SecretBuffer::from_str(&req.backup_passphrase))
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CreateBackupResponse {
            encrypted_archive: archive,
            archive_sha256: sha256,
        }))
    }

    async fn restore_backup(
        &self,
        request: Request<RestoreBackupRequest>,
    ) -> Result<Response<RestoreBackupResponse>, Status> {
        let req = request.into_inner();
        let mut state = self.state.write().await;

        let restored_bytes = restore_dr_backup(&req.encrypted_archive, &SecretBuffer::from_str(&req.backup_passphrase))
            .map_err(|e| Status::internal(e.to_string()))?;

        let db: VaultDatabase = serde_json::from_slice(&restored_bytes)
            .map_err(|e| Status::invalid_argument(format!("Failed to parse restored vault DB: {}", e)))?;

        state.vault_db = db;
        state.persist().map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RestoreBackupResponse {
            success: true,
            message: "Vault database restored successfully".to_string(),
        }))
    }
}
