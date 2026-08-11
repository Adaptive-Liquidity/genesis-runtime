use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::authority::{LeaseRef, SignatureBytes};
use crate::digest::{canonical_bytes, canonical_digest, CanonicalJson, Digest};
use crate::error::{ErrorCode, Result, RuntimeError};
use crate::ids::{AgentId, AuthorizationId, CertificateId, LeaseId, MissionId, ToolId};

pub const MAX_ACTION_TARGET_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ActionTarget(String);

impl ActionTarget {
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let value = value.as_ref();
        if value.trim().is_empty() || value.len() > MAX_ACTION_TARGET_BYTES {
            return Err(RuntimeError::new(
                ErrorCode::InvalidInput,
                format!("action target must contain 1 to {MAX_ACTION_TARGET_BYTES} bytes"),
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(RuntimeError::new(
                ErrorCode::InvalidInput,
                "action target must not contain control characters",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<'de> Deserialize<'de> for ActionTarget {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    ReadOnly,
    Idempotent,
    NonIdempotent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticScope {
    Mission,
    Agent,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalAction {
    pub mission_id: MissionId,
    pub effect_kind: EffectClass,
    pub target: ActionTarget,
    pub normalized_parameters: CanonicalJson,
    pub semantic_scope: SemanticScope,
}

impl CanonicalAction {
    pub fn action_ref(&self) -> Result<ActionRef> {
        canonical_digest("aeon-canonical-action-v1", self).map(ActionRef)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActionRef(Digest);

impl ActionRef {
    pub const fn new(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(&self) -> &Digest {
        &self.0
    }

    pub const fn into_digest(self) -> Digest {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBinding {
    pub action_ref: ActionRef,
    pub agent_id: AgentId,
    pub tool_id: ToolId,
    pub tool_manifest_digest: Digest,
    pub organization_version: u64,
    pub policy_epoch: u64,
    pub semantic_context_digest: Digest,
    pub concrete_input_digest: Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationState {
    Issued,
    Prepared,
    Consumed,
    Aborted,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectState {
    None,
    Staged,
    CommitDecided,
    Released,
    Confirmed,
    UnknownOutcome,
    Aborted,
    Compensated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub actions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRecord {
    pub record_id: AuthorizationId,
    pub action_ref: ActionRef,
    pub authority_chain: Vec<LeaseRef>,
    pub total_budget: Budget,
    pub remaining_budget: Budget,
    pub state: AuthorizationState,
    pub stable_idempotency_key: String,
    pub effect_class: EffectClass,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRecord {
    pub action_ref: ActionRef,
    pub authorization_id: AuthorizationId,
    pub state: EffectState,
    pub reconciliation_required: bool,
    pub escalation_target: Option<String>,
}

/// Immutable signed authorization credential. Consumption belongs to AuthorizationRecord.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionCertificate {
    pub certificate_id: CertificateId,
    pub mission_id: MissionId,
    pub agent_identity_digest: Digest,
    pub authority_lease_id: LeaseId,
    pub organization_version: u64,
    pub policy_epoch: u64,
    pub semantic_context_digest: Digest,
    pub action_ref: ActionRef,
    pub tool_id: ToolId,
    pub tool_manifest_digest: Digest,
    pub concrete_input_digest: Digest,
    pub authorization_record_id: AuthorizationId,
    pub granted_uses: u32,
    pub authorization_generation: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature: SignatureBytes,
}

impl ActionCertificate {
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct SigningPayload<'a> {
            certificate_id: &'a CertificateId,
            mission_id: &'a MissionId,
            agent_identity_digest: &'a Digest,
            authority_lease_id: &'a LeaseId,
            organization_version: u64,
            policy_epoch: u64,
            semantic_context_digest: &'a Digest,
            action_ref: &'a ActionRef,
            tool_id: &'a ToolId,
            tool_manifest_digest: &'a Digest,
            concrete_input_digest: &'a Digest,
            authorization_record_id: &'a AuthorizationId,
            granted_uses: u32,
            authorization_generation: u64,
            issued_at: &'a DateTime<Utc>,
            expires_at: &'a DateTime<Utc>,
        }
        let ActionCertificate {
            certificate_id,
            mission_id,
            agent_identity_digest,
            authority_lease_id,
            organization_version,
            policy_epoch,
            semantic_context_digest,
            action_ref,
            tool_id,
            tool_manifest_digest,
            concrete_input_digest,
            authorization_record_id,
            granted_uses,
            authorization_generation,
            issued_at,
            expires_at,
            signature: _,
        } = self;

        canonical_bytes(
            "aeon-action-certificate-v1",
            &SigningPayload {
                certificate_id,
                mission_id,
                agent_identity_digest,
                authority_lease_id,
                organization_version: *organization_version,
                policy_epoch: *policy_epoch,
                semantic_context_digest,
                action_ref,
                tool_id,
                tool_manifest_digest,
                concrete_input_digest,
                authorization_record_id,
                granted_uses: *granted_uses,
                authorization_generation: *authorization_generation,
                issued_at,
                expires_at,
            },
        )
    }
}
