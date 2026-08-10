use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use nexus::Capability;
use serde::{Deserialize, Serialize};

use crate::digest::{canonical_bytes, canonical_digest, canonical_value_bytes, Digest};
use crate::error::{ErrorCode, Result, RuntimeError};
use crate::ids::{AgentId, LeaseId, MissionId, ToolId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRequest {
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySet {
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionSet {
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundTool {
    pub tool_id: ToolId,
    pub tool_manifest_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityManifest {
    pub version: u8,
    pub model_manifest_digest: Digest,
    pub approved_tools: Vec<BoundTool>,
    pub permissions: PermissionSet,
    pub runtime_config_digest: Digest,
    pub tool_registry_root_digest: Digest,
}

impl CapabilityManifest {
    pub fn canonical_digest(&self) -> Result<Digest> {
        #[derive(Serialize)]
        struct CanonicalManifest<'a> {
            version: u8,
            model_manifest_digest: &'a Digest,
            approved_tools: Vec<BoundTool>,
            permissions: PermissionSet,
            runtime_config_digest: &'a Digest,
            tool_registry_root_digest: &'a Digest,
        }

        let mut approved_tools = self.approved_tools.clone();
        approved_tools.sort_unstable();
        approved_tools.dedup();
        canonical_digest(
            "aeon-capability-manifest-v1",
            &CanonicalManifest {
                version: self.version,
                model_manifest_digest: &self.model_manifest_digest,
                approved_tools,
                permissions: PermissionSet {
                    capabilities: canonical_capabilities(&self.permissions.capabilities)?,
                },
                runtime_config_digest: &self.runtime_config_digest,
                tool_registry_root_digest: &self.tool_registry_root_digest,
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignatureBytes(Vec<u8>);

impl SignatureBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityLeaseCertificate {
    pub lease_id: LeaseId,
    pub mission_id: MissionId,
    pub agent_id: AgentId,
    pub parent_agent_id: Option<AgentId>,
    pub organization_version: u64,
    pub policy_epoch: u64,
    pub granted_authority: AuthoritySet,
    pub delegable_authority: AuthoritySet,
    pub capability_manifest_digest: Digest,
    pub semantic_context_digest: Digest,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature: SignatureBytes,
}

impl AuthorityLeaseCertificate {
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct SigningPayload<'a> {
            lease_id: &'a LeaseId,
            mission_id: &'a MissionId,
            agent_id: &'a AgentId,
            parent_agent_id: &'a Option<AgentId>,
            organization_version: u64,
            policy_epoch: u64,
            granted_authority: AuthoritySet,
            delegable_authority: AuthoritySet,
            capability_manifest_digest: &'a Digest,
            semantic_context_digest: &'a Digest,
            issued_at: &'a DateTime<Utc>,
            expires_at: &'a DateTime<Utc>,
        }

        canonical_bytes(
            "aeon-authority-lease-certificate-v1",
            &SigningPayload {
                lease_id: &self.lease_id,
                mission_id: &self.mission_id,
                agent_id: &self.agent_id,
                parent_agent_id: &self.parent_agent_id,
                organization_version: self.organization_version,
                policy_epoch: self.policy_epoch,
                granted_authority: AuthoritySet {
                    capabilities: canonical_capabilities(&self.granted_authority.capabilities)?,
                },
                delegable_authority: AuthoritySet {
                    capabilities: canonical_capabilities(&self.delegable_authority.capabilities)?,
                },
                capability_manifest_digest: &self.capability_manifest_digest,
                semantic_context_digest: &self.semantic_context_digest,
                issued_at: &self.issued_at,
                expires_at: &self.expires_at,
            },
        )
    }

    /// Verifies the immutable certificate payload and fails closed for malformed signatures.
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<()> {
        let signature_bytes = <[u8; 64]>::try_from(self.signature.as_bytes()).map_err(|_| {
            RuntimeError::new(
                ErrorCode::AuthorizationInvalid,
                "lease certificate signature must contain exactly 64 bytes",
            )
        })?;
        let payload = self.signing_payload()?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key.verify(&payload, &signature).map_err(|_| {
            RuntimeError::new(
                ErrorCode::AuthorizationInvalid,
                "lease certificate signature verification failed",
            )
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Active,
    Revoked,
    Expired,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRecord {
    pub lease_id: LeaseId,
    pub state: LeaseState,
    pub generation: u64,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
}

impl LeaseRecord {
    pub fn active(lease_id: LeaseId) -> Self {
        Self {
            lease_id,
            state: LeaseState::Active,
            generation: 0,
            revoked_at: None,
            revocation_reason: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRef {
    pub lease_id: LeaseId,
    pub certificate_digest: Digest,
}

pub(crate) fn canonical_capabilities(capabilities: &[Capability]) -> Result<Vec<Capability>> {
    let mut keyed = Vec::with_capacity(capabilities.len());
    for capability in capabilities {
        let value = serde_json::to_value(capability).map_err(|error| {
            RuntimeError::new(ErrorCode::CanonicalSerialization, error.to_string())
        })?;
        keyed.push((canonical_value_bytes(&value)?, capability.clone()));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    keyed.dedup_by(|left, right| left.0 == right.0);
    Ok(keyed
        .into_iter()
        .map(|(_, capability)| capability)
        .collect())
}
