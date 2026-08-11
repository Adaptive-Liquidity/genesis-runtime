use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use nexus::Capability;
use serde::{Deserialize, Deserializer, Serialize};

use crate::digest::{canonical_bytes, canonical_digest, canonical_value_bytes, Digest};
use crate::error::{ErrorCode, Result, RuntimeError};
use crate::ids::{AgentId, KeyId, LeaseId, MissionId, ToolId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRequest {
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySet {
    capabilities: Vec<Capability>,
}

impl AuthoritySet {
    pub fn new(capabilities: Vec<Capability>) -> Result<Self> {
        if capabilities
            .iter()
            .any(|capability| capability == &Capability::All)
        {
            return Err(RuntimeError::new(
                ErrorCode::CapabilityAllForbidden,
                "Capability::All is forbidden in agent authority",
            ));
        }
        Ok(Self {
            capabilities: canonical_capabilities(&capabilities)?,
        })
    }

    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    pub fn covers(&self, required: &Capability) -> bool {
        self.capabilities
            .iter()
            .any(|granted| required.is_subset_of(granted))
    }

    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.capabilities
            .iter()
            .all(|capability| parent.covers(capability))
    }
}

impl<'de> Deserialize<'de> for AuthoritySet {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SerializedAuthoritySet {
            capabilities: Vec<Capability>,
        }

        let serialized = SerializedAuthoritySet::deserialize(deserializer)?;
        Self::new(serialized.capabilities).map_err(serde::de::Error::custom)
    }
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

        let mut tool_ids = std::collections::HashSet::with_capacity(self.approved_tools.len());
        if self
            .approved_tools
            .iter()
            .any(|tool| !tool_ids.insert(tool.tool_id.clone()))
        {
            return Err(RuntimeError::new(
                ErrorCode::CapabilityManifestMismatch,
                "capability manifest contains duplicate tool identifiers",
            ));
        }

        let mut approved_tools = self.approved_tools.clone();
        approved_tools.sort_unstable();
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
    pub agent_identity_digest: Digest,
    pub issuer_identity_digest: Digest,
    pub issuer_key_id: KeyId,
    pub parent_lease: Option<LeaseRef>,
    pub renewed_from: Option<LeaseRef>,
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
            agent_identity_digest: &'a Digest,
            issuer_identity_digest: &'a Digest,
            issuer_key_id: &'a KeyId,
            parent_lease: &'a Option<LeaseRef>,
            renewed_from: &'a Option<LeaseRef>,
            organization_version: u64,
            policy_epoch: u64,
            granted_authority: &'a AuthoritySet,
            delegable_authority: &'a AuthoritySet,
            capability_manifest_digest: &'a Digest,
            semantic_context_digest: &'a Digest,
            issued_at: &'a DateTime<Utc>,
            expires_at: &'a DateTime<Utc>,
        }

        let AuthorityLeaseCertificate {
            lease_id,
            mission_id,
            agent_id,
            parent_agent_id,
            agent_identity_digest,
            issuer_identity_digest,
            issuer_key_id,
            parent_lease,
            renewed_from,
            organization_version,
            policy_epoch,
            granted_authority,
            delegable_authority,
            capability_manifest_digest,
            semantic_context_digest,
            issued_at,
            expires_at,
            signature: _,
        } = self;

        canonical_bytes(
            "aeon-authority-lease-certificate-v2",
            &SigningPayload {
                lease_id,
                mission_id,
                agent_id,
                parent_agent_id,
                agent_identity_digest,
                issuer_identity_digest,
                issuer_key_id,
                parent_lease,
                renewed_from,
                organization_version: *organization_version,
                policy_epoch: *policy_epoch,
                granted_authority,
                delegable_authority,
                capability_manifest_digest,
                semantic_context_digest,
                issued_at,
                expires_at,
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
    Paused,
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
    pub renewed_by: Option<LeaseId>,
}

impl LeaseRecord {
    pub fn active(lease_id: LeaseId) -> Self {
        Self {
            lease_id,
            state: LeaseState::Active,
            generation: 0,
            revoked_at: None,
            revocation_reason: None,
            renewed_by: None,
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
