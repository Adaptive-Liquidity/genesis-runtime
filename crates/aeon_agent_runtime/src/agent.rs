use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::authority::AuthorityRequest;
use crate::digest::{canonical_digest, Digest};
use crate::error::{ErrorCode, Result, RuntimeError};
use crate::ids::{
    AgentId, InstructionProfileRef, LeaseId, MemoryRef, ModelRef, RetrievalIndexRef, ToolId,
};

const MAX_DECLARATIVE_TEXT_BYTES: usize = 4096;

fn validate_declarative_text(kind: &'static str, value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > MAX_DECLARATIVE_TEXT_BYTES {
        return Err(RuntimeError::new(
            ErrorCode::InvalidInput,
            format!("{kind} must contain 1 to {MAX_DECLARATIVE_TEXT_BYTES} bytes"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(RuntimeError::new(
            ErrorCode::InvalidInput,
            format!("{kind} must not contain control characters"),
        ));
    }
    Ok(())
}

macro_rules! declarative_text {
    ($name:ident, $kind:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl AsRef<str>) -> Result<Self> {
                let value = value.as_ref();
                validate_declarative_text($kind, value)?;
                Ok(Self(value.to_owned()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

declarative_text!(Role, "role");
declarative_text!(Objective, "objective");
declarative_text!(Contract, "output contract");

/// Untrusted, declarative request. Trusted bindings and lifecycle state live elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSpec {
    pub role: Role,
    pub objective: Objective,
    pub requested_model: ModelRef,
    pub requested_tools: Vec<ToolId>,
    pub requested_authority: AuthorityRequest,
    pub output_contract: Contract,
    pub resource_budget: ResourceRequest,
    pub semantic_requirements: SemanticRequirements,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRequest {
    pub max_steps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticRequirements {
    pub requested_memory: Option<MemoryRef>,
    pub requested_retrieval_index: Option<RetrievalIndexRef>,
    pub requested_instruction_profile: Option<InstructionProfileRef>,
}

/// Trusted resolution of the resources that materially determine agent behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticContext {
    /// Ordering/audit metadata; deliberately excluded from semantic identity.
    pub context_version: u64,
    pub model_manifest_digest: Digest,
    pub resolved_system_instruction_digest: Digest,
    pub tool_registry_root_digest: Digest,
    pub bound_tool_digests: Vec<Digest>,
    pub protocol_schema_digest: Digest,
    pub policy_epoch: u64,
    pub memory_generation: Option<Digest>,
    pub retrieval_index_generation: Option<Digest>,
}

impl SemanticContext {
    pub fn canonical_digest(&self) -> Result<Digest> {
        #[derive(Serialize)]
        struct Identity<'a> {
            model_manifest_digest: &'a Digest,
            resolved_system_instruction_digest: &'a Digest,
            tool_registry_root_digest: &'a Digest,
            bound_tool_digests: Vec<Digest>,
            protocol_schema_digest: &'a Digest,
            policy_epoch: u64,
            memory_generation: &'a Option<Digest>,
            retrieval_index_generation: &'a Option<Digest>,
        }

        let mut bound_tool_digests = self.bound_tool_digests.clone();
        bound_tool_digests.sort_unstable();
        bound_tool_digests.dedup();
        canonical_digest(
            "aeon-semantic-context-v1",
            &Identity {
                model_manifest_digest: &self.model_manifest_digest,
                resolved_system_instruction_digest: &self.resolved_system_instruction_digest,
                tool_registry_root_digest: &self.tool_registry_root_digest,
                bound_tool_digests,
                protocol_schema_digest: &self.protocol_schema_digest,
                policy_epoch: self.policy_epoch,
                memory_generation: &self.memory_generation,
                retrieval_index_generation: &self.retrieval_index_generation,
            },
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextTransition {
    Exact,
}

pub fn validate_context_continuation(
    original_digest: &Digest,
    current: &SemanticContext,
) -> Result<ContextTransition> {
    if original_digest == &current.canonical_digest()? {
        Ok(ContextTransition::Exact)
    } else {
        Err(RuntimeError::new(
            ErrorCode::SemanticContextChanged,
            "material semantic context differs from the authorized context",
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLifecycle {
    Proposed,
    Authorized,
    Active,
    Paused,
    Revoked,
    Terminated,
    Compromised,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIdentity {
    pub agent_id: AgentId,
    pub identity_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeRecord {
    pub spec_digest: Digest,
    pub identity: AgentIdentity,
    pub lease_id: LeaseId,
    pub lifecycle: AgentLifecycle,
    pub current_step: u64,
    pub semantic_context: SemanticContext,
    pub semantic_context_digest: Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityLevel {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTrust {
    Untrusted,
    Advisory,
    SourceVerified,
    SystemAttested,
}

/// Trust-classified advisory memory shape. R1 does not integrate a memory backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryEntry {
    pub content: Vec<u8>,
    pub checksum: Digest,
    pub confidentiality: SecurityLevel,
    pub integrity: SecurityLevel,
    pub source_agent: AgentId,
    pub source_identity_digest: Digest,
    pub created_at: DateTime<Utc>,
    pub trust_class: MemoryTrust,
    pub ttl_seconds: u32,
    pub expires_at: DateTime<Utc>,
    pub semantic_context_digest: Digest,
}
