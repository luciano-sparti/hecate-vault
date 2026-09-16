use anyhow::Result;
use hecate_protocol::agent::agent_service_client::AgentServiceClient;
use hecate_protocol::agent::*;
use tonic::transport::Channel;

pub struct AgentClient {
    inner: AgentServiceClient<Channel>,
}

impl AgentClient {
    pub async fn connect(core_url: String) -> Result<Self> {
        let channel = Channel::from_shared(core_url)?
            .connect()
            .await?;
        let inner = AgentServiceClient::new(channel);
        Ok(Self { inner })
    }

    pub async fn enroll(
        &mut self,
        token: String,
        hostname: String,
        os_info: String,
    ) -> Result<EnrollResponse> {
        let req = EnrollRequest {
            one_time_token: token,
            hostname,
            os_info,
            client_csr: String::new(),
        };
        let res = self.inner.enroll_agent(req).await?;
        Ok(res.into_inner())
    }

    pub async fn heartbeat(
        &mut self,
        agent_id: String,
        active_guard_points: u32,
    ) -> Result<HeartbeatResponse> {
        let req = HeartbeatRequest {
            agent_id,
            timestamp: chrono::Utc::now().timestamp(),
            active_guard_points,
            agent_version: "0.2.0".to_string(),
        };
        let res = self.inner.heartbeat(req).await?;
        Ok(res.into_inner())
    }

    pub async fn sync_policies(
        &mut self,
        agent_id: String,
        version: u32,
    ) -> Result<SyncPolicyResponse> {
        let req = SyncPolicyRequest {
            agent_id,
            current_policy_version: version,
        };
        let res = self.inner.sync_policies(req).await?;
        Ok(res.into_inner())
    }

    pub async fn report_compliance(
        &mut self,
        agent_id: String,
        items: Vec<GuardPointCompliance>,
    ) -> Result<ComplianceReportResponse> {
        let req = ComplianceReportRequest {
            agent_id,
            timestamp: chrono::Utc::now().timestamp(),
            items,
        };
        let res = self.inner.report_compliance(req).await?;
        Ok(res.into_inner())
    }

    pub async fn fetch_guard_key(
        &mut self,
        agent_id: String,
        policy_id: String,
        key_id: String,
    ) -> Result<GuardKeyResponse> {
        let req = GuardKeyRequest {
            agent_id,
            policy_id,
            key_id,
        };
        let res = self.inner.fetch_guard_key(req).await?;
        Ok(res.into_inner())
    }
}
