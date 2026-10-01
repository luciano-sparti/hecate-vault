use crate::server::CoreState;
use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

/// Thread-safe Prometheus metrics collector and exporter for Hecate Core.
#[derive(Debug, Default)]
pub struct HecateMetrics {
    crypto_ops: RwLock<HashMap<String, AtomicU64>>,
    access_denials: RwLock<HashMap<String, AtomicU64>>,
    heartbeats_total: AtomicU64,
}

impl HecateMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a cryptographic operation performed by the Software HSM.
    pub async fn record_crypto_op(&self, op: &str, key_id: &str) {
        let key = format!("operation=\"{}\",key_id=\"{}\"", op, key_id);
        let mut map = self.crypto_ops.write().await;
        let counter = map.entry(key).or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an unauthorized access denial on a Guard Point.
    pub async fn record_access_denial(&self, policy_id: &str, reason: &str) {
        let key = format!("policy_id=\"{}\",reason=\"{}\"", policy_id, reason);
        let mut map = self.access_denials.write().await;
        let counter = map.entry(key).or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an agent heartbeat event.
    pub fn record_heartbeat(&self) {
        self.heartbeats_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Render Prometheus exposition format text.
    pub async fn render_prometheus(&self, state: &CoreState) -> String {
        let mut out = String::new();

        // 1. HSM Crypto Operations Counter
        out.push_str("# HELP hecate_hsm_crypto_ops_total Total cryptographic operations performed by Software HSM\n");
        out.push_str("# TYPE hecate_hsm_crypto_ops_total counter\n");
        {
            let map = self.crypto_ops.read().await;
            if map.is_empty() {
                out.push_str("hecate_hsm_crypto_ops_total{operation=\"none\",key_id=\"none\"} 0\n");
            } else {
                for (labels, val) in map.iter() {
                    out.push_str(&format!(
                        "hecate_hsm_crypto_ops_total{{{}}} {}\n",
                        labels,
                        val.load(Ordering::Relaxed)
                    ));
                }
            }
        }
        out.push('\n');

        // 2. Guard Point Access Denials Counter
        out.push_str("# HELP hecate_guard_access_denials_total Total Guard Point unauthorized access denials\n");
        out.push_str("# TYPE hecate_guard_access_denials_total counter\n");
        {
            let map = self.access_denials.read().await;
            if map.is_empty() {
                out.push_str("hecate_guard_access_denials_total{policy_id=\"none\",reason=\"none\"} 0\n");
            } else {
                for (labels, val) in map.iter() {
                    out.push_str(&format!(
                        "hecate_guard_access_denials_total{{{}}} {}\n",
                        labels,
                        val.load(Ordering::Relaxed)
                    ));
                }
            }
        }
        out.push('\n');

        // 3. Agent Heartbeats Total Counter
        out.push_str("# HELP hecate_agent_heartbeats_total Total agent heartbeat ping messages processed\n");
        out.push_str("# TYPE hecate_agent_heartbeats_total counter\n");
        out.push_str(&format!(
            "hecate_agent_heartbeats_total {}\n\n",
            self.heartbeats_total.load(Ordering::Relaxed)
        ));

        // 4. Audit Chain Length Gauge
        out.push_str("# HELP hecate_audit_chain_length Total blocks in the tamper-evident cryptographic hash-chain\n");
        out.push_str("# TYPE hecate_audit_chain_length gauge\n");
        let audit_len = state.audit_ledger.entries().len();
        out.push_str(&format!("hecate_audit_chain_length {}\n\n", audit_len));

        // 5. Active Policies Gauge
        out.push_str("# HELP hecate_active_policies_total Total registered Guard Point policies\n");
        out.push_str("# TYPE hecate_active_policies_total gauge\n");
        let policy_count = state.policy_store.list_policies().len();
        out.push_str(&format!("hecate_active_policies_total {}\n\n", policy_count));

        // 6. Registered Agents Gauge
        out.push_str("# HELP hecate_registered_agents_total Total enrolled agent nodes\n");
        out.push_str("# TYPE hecate_registered_agents_total gauge\n");
        let agent_count = state.agent_registry.list_agents().len();
        out.push_str(&format!("hecate_registered_agents_total {}\n", agent_count));

        out
    }

    /// Start a lightweight HTTP listener serving GET /metrics.
    pub async fn start_metrics_server(
        addr: SocketAddr,
        state: Arc<RwLock<CoreState>>,
        metrics: Arc<HecateMetrics>,
    ) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(res) => res,
                    Err(_) => break,
                };

                let state = state.clone();
                let metrics = metrics.clone();

                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let req_str = String::from_utf8_lossy(&buf[..n]);

                    if req_str.starts_with("GET /metrics") || req_str.starts_with("GET / ") {
                        let st = state.read().await;
                        let body = metrics.render_prometheus(&st).await;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else {
                        let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        let _ = socket.write_all(not_found.as_bytes()).await;
                    }
                });
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_prometheus_metrics_rendering() {
        let dir = tempfile::tempdir().unwrap();
        let state_arc = crate::load_or_init_core_state(dir.path()).unwrap();
        let state = state_arc.read().await;
        let metrics = HecateMetrics::new();
        metrics.record_crypto_op("encrypt", "key-01").await;
        metrics.record_crypto_op("decrypt", "key-01").await;
        metrics.record_access_denial("gp-db", "unauthorized_root").await;
        metrics.record_heartbeat();

        let rendered = metrics.render_prometheus(&state).await;
        assert!(rendered.contains("hecate_hsm_crypto_ops_total{operation=\"encrypt\",key_id=\"key-01\"} 1"));
        assert!(rendered.contains("hecate_hsm_crypto_ops_total{operation=\"decrypt\",key_id=\"key-01\"} 1"));
        assert!(rendered.contains("hecate_guard_access_denials_total{policy_id=\"gp-db\",reason=\"unauthorized_root\"} 1"));
        assert!(rendered.contains("hecate_agent_heartbeats_total 1"));
        assert!(rendered.contains("hecate_audit_chain_length"));
    }
}
