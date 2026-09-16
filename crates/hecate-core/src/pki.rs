use anyhow::{anyhow, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPkiStore {
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
}

pub struct InternalCertificateAuthority {
    pub ca_cert_pem: String,
    ca_key_pair: KeyPair,
    ca_cert: Certificate,
}

impl InternalCertificateAuthority {
    fn build_ca_params() -> CertificateParams {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        params
            .distinguished_name
            .push(DnType::CommonName, "Hecate Internal Root CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Hecate Security Ecosystem");
        params
    }

    pub fn generate_or_load(path: &Path) -> Result<Self> {
        if path.exists() {
            let contents = fs::read_to_string(path)?;
            let store: InternalPkiStore = serde_json::from_str(&contents)?;
            let key_pair = KeyPair::from_pem(&store.ca_key_pem)
                .map_err(|e| anyhow!("Failed to parse CA key PEM: {}", e))?;
            
            let ca_params = Self::build_ca_params();
            let ca_cert = ca_params
                .self_signed(&key_pair)
                .map_err(|e| anyhow!("Failed to rebuild CA certificate: {}", e))?;

            Ok(Self {
                ca_cert_pem: store.ca_cert_pem,
                ca_key_pair: key_pair,
                ca_cert,
            })
        } else {
            let ca_key_pair = KeyPair::generate()
                .map_err(|e| anyhow!("Failed to generate CA keypair: {}", e))?;

            let ca_params = Self::build_ca_params();
            let ca_cert = ca_params
                .self_signed(&ca_key_pair)
                .map_err(|e| anyhow!("Failed to self-sign Root CA: {}", e))?;

            let ca_cert_pem = ca_cert.pem();
            let ca_key_pem = ca_key_pair.serialize_pem();

            let store = InternalPkiStore {
                ca_cert_pem: ca_cert_pem.clone(),
                ca_key_pem,
            };

            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let serialized = serde_json::to_string_pretty(&store)?;
            fs::write(path, serialized)?;

            Ok(Self {
                ca_cert_pem,
                ca_key_pair,
                ca_cert,
            })
        }
    }

    pub fn issue_client_certificate(
        &self,
        hostname: &str,
        agent_id: &str,
    ) -> Result<(String, String, i64)> {
        let client_key_pair = KeyPair::generate()
            .map_err(|e| anyhow!("Failed to generate client keypair: {}", e))?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
        params
            .distinguished_name
            .push(DnType::CommonName, format!("hecate-agent-{}", agent_id));
        params
            .distinguished_name
            .push(DnType::OrganizationName, format!("Hecate Agent Node {}", hostname));

        let cert = params
            .signed_by(&client_key_pair, &self.ca_cert, &self.ca_key_pair)
            .map_err(|e| anyhow!("Failed to sign client certificate: {}", e))?;

        let client_cert_pem = cert.pem();
        let client_key_pem = client_key_pair.serialize_pem();
        let expires_at = chrono::Utc::now().timestamp() + (90 * 86400); // 90 days

        Ok((client_cert_pem, client_key_pem, expires_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_pki_ca_generation_and_client_cert_issuance() -> Result<()> {
        let dir = tempdir()?;
        let pki_path = dir.path().join("pki.json");

        // 1. Generate new CA
        let ca = InternalCertificateAuthority::generate_or_load(&pki_path)?;
        assert!(ca.ca_cert_pem.contains("BEGIN CERTIFICATE"));

        // 2. Issue client certificate
        let (cert_pem, key_pem, expires_at) = ca.issue_client_certificate("node-test", "agent-101")?;
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(expires_at > chrono::Utc::now().timestamp());

        // 3. Load existing CA from disk
        let loaded_ca = InternalCertificateAuthority::generate_or_load(&pki_path)?;
        assert_eq!(ca.ca_cert_pem, loaded_ca.ca_cert_pem);

        Ok(())
    }
}
