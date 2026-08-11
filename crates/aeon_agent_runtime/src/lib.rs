#![forbid(unsafe_code)]
//! AEON's governed host-side agent runtime.

pub mod action;
pub mod agent;
pub mod authority;
pub mod authority_kernel;
pub mod context;
pub mod digest;
pub mod error;
mod execution;
pub mod identity;
pub mod ids;
pub mod mission;
pub mod model;
pub mod protocol;
pub mod store;
pub mod supervisor;
pub mod tool_registry;

pub use action::{
    ActionCertificate, ActionRef, ActionTarget, AuthorizationRecord, AuthorizationState, Budget,
    CanonicalAction, EffectClass, EffectRecord, EffectState, ExecutionBinding, SemanticScope,
    MAX_ACTION_TARGET_BYTES,
};
pub use agent::{
    validate_context_continuation, AgentIdentity, AgentLifecycle, AgentRuntimeRecord, AgentSpec,
    ContextTransition, Contract, MemoryEntry, MemoryTrust, Objective, ResourceRequest, Role,
    SecurityLevel, SemanticContext, SemanticRequirements, MAX_AGENT_STEPS,
    MAX_REQUESTED_CAPABILITIES, MAX_REQUESTED_TOOLS,
};
pub use authority::{
    AuthorityLeaseCertificate, AuthorityRequest, AuthoritySet, BoundTool, CapabilityManifest,
    LeaseRecord, LeaseRef, LeaseState, PermissionSet, SignatureBytes,
};
pub use authority_kernel::{
    AuthorityEvent, AuthorityEventKind, AuthorityKernel, DelegationRequest, LeaseSnapshot,
    RenewalRequest, RootLeaseRequest, ValidatedAuthority, MAX_AUTHORITY_CHAIN_DEPTH,
};
pub use digest::{canonical_bytes, canonical_digest, CanonicalJson, Digest};
pub use error::{ErrorCode, RuntimeError};
pub use identity::{AgentIdentityCertificate, InMemoryKeyCustody, KeyCustody};
pub use ids::{
    AgentId, AuthorizationId, CertificateId, InstructionProfileRef, KeyId, LeaseId, MemoryRef,
    MissionId, ModelRef, RetrievalIndexRef, ToolId,
};
pub use mission::MissionEnvelope;
pub use model::{ModelClient, ModelRequest, ModelResponse};
pub use protocol::{
    AgentMessage, FinalResult, ProtocolGate, ToolCallProposal, DEFAULT_MAX_OUTPUT_BYTES,
};
pub use store::{InMemoryMissionStore, MissionEvent, MissionEventKind};
pub use supervisor::{R1Metrics, R1Runtime, R2Runtime, RunOutcome};
pub use tool_registry::{RegisteredTool, ToolManifest, ToolRegistry};
