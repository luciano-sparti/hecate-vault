use anyhow::{anyhow, Result};
use chrono::Utc;
use hecate_protocol::admin::AgentInfo;
use hecate_protocol::agent::GuardPointCompliance;
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use tempfile::NamedTempFile;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentToken {
    pub token: String,
    pub hostname: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredAgent {
    pub agent_id: String,
    pub hostname: String,
    pub os_info: String,
    pub enrolled_at: i64,
    pub last_heartbeat: i64,
    pub is_revoked: bool,
    pub compliance_status: String,
    pub latest_compliance_items: Vec<GuardPointCompliance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRegistry {
    tokens: HashMap<String, EnrollmentToken>,
    agents: HashMap<String, RegisteredAgent>,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self {
            tokens: HashMap::new(),
            agents: HashMap::new(),
        }
    }

    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let mut file = File::open(path)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            let registry: AgentRegistry = serde_json::from_str(&contents)?;
            Ok(registry)
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

    pub fn generate_token(&mut self, hostname: &str, validity_seconds: i64) -> EnrollmentToken {
        let mut token_bytes = [0u8; 16];
        thread_rng().fill_bytes(&mut token_bytes);
        let token_str = format!("HCT-TKN-{}", hex::encode(token_bytes));
        let now = Utc::now().timestamp();

        let token = EnrollmentToken {
            token: token_str.clone(),
            hostname: hostname.to_string(),
            created_at: now,
            expires_at: now + validity_seconds,
            used: false,
        };

        self.tokens.insert(token_str, token.clone());
        token
    }

    pub fn validate_and_consume_token(&mut self, token_str: &str) -> Result<String> {
        let token = self
            .tokens
            .get_mut(token_str)
            .ok_or_else(|| anyhow!("Enrollment token not found or invalid"))?;

        if token.used {
            return Err(anyhow!("Enrollment token has already been consumed"));
        }

        let now = Utc::now().timestamp();
        if now > token.expires_at {
            return Err(anyhow!("Enrollment token has expired"));
        }

        token.used = true;
        let mut id_bytes = [0u8; 8];
        thread_rng().fill_bytes(&mut id_bytes);
        let agent_id = format!("agent-{}", hex::encode(id_bytes));
        Ok(agent_id)
    }

    pub fn register_agent(
        &mut self,
        agent_id: String,
        hostname: String,
        os_info: String,
    ) -> RegisteredAgent {
        let now = Utc::now().timestamp();
        let agent = RegisteredAgent {
            agent_id: agent_id.clone(),
            hostname,
            os_info,
            enrolled_at: now,
            last_heartbeat: now,
            is_revoked: false,
            compliance_status: "COMPLIANT".to_string(),
            latest_compliance_items: Vec::new(),
        };

        self.agents.insert(agent_id, agent.clone());
        agent
    }

    pub fn record_heartbeat(&mut self, agent_id: &str) -> Result<()> {
        let agent = self
            .agents
            .get_mut(agent_id)
            .ok_or_else(|| anyhow!("Agent '{}' not registered", agent_id))?;

        if agent.is_revoked {
            return Err(anyhow!("Agent certificate has been revoked"));
        }

        agent.last_heartbeat = Utc::now().timestamp();
        Ok(())
    }

    pub fn update_compliance(
        &mut self,
        agent_id: &str,
        items: Vec<GuardPointCompliance>,
    ) -> Result<()> {
        let agent = self
            .agents
            .get_mut(agent_id)
            .ok_or_else(|| anyhow!("Agent '{}' not registered", agent_id))?;

        let has_violations = items.iter().any(|i| i.status != "COMPLIANT" || i.access_violations_count > 0);
        agent.compliance_status = if has_violations {
            "NON_COMPLIANT".to_string()
        } else {
            "COMPLIANT".to_string()
        };
        agent.latest_compliance_items = items;
        agent.last_heartbeat = Utc::now().timestamp();

        Ok(())
    }

    pub fn revoke_agent(&mut self, agent_id: &str) -> Result<()> {
        let agent = self
            .agents
            .get_mut(agent_id)
            .ok_or_else(|| anyhow!("Agent '{}' not found", agent_id))?;
        agent.is_revoked = true;
        Ok(())
    }

    pub fn get_registered_agent(&self, agent_id: &str) -> Option<&RegisteredAgent> {
        self.agents.get(agent_id)
    }

    pub fn list_agents(&self) -> Vec<AgentInfo> {
        self.agents
            .values()
            .map(|a| AgentInfo {
                agent_id: a.agent_id.clone(),
                hostname: a.hostname.clone(),
                os_info: a.os_info.clone(),
                enrolled_at: a.enrolled_at,
                last_heartbeat: a.last_heartbeat,
                compliance_status: a.compliance_status.clone(),
                is_revoked: a.is_revoked,
            })
            .collect()
    }
}
