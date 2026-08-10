use serde::Serialize;

use crate::agent::{AgentSpec, SemanticContext};
use crate::digest::{canonical_digest, Digest};
use crate::error::{ErrorCode, RuntimeError};
use crate::tool_registry::ToolRegistry;

const PROTOCOL_SCHEMA: &str = r#"{"kind":"tool_call","tool_id":"ToolId","arguments":"object"}|{"kind":"final","result":"string"}"#;

/// Trusted inputs used to resolve the semantic reality bound to an agent.
#[derive(Debug, Clone)]
pub struct ContextResolver {
    model_manifest_digest: Digest,
    protocol_schema_digest: Digest,
    policy_epoch: u64,
    context_version: u64,
}

impl ContextResolver {
    pub fn new(
        model_manifest_digest: Digest,
        protocol_schema_digest: Digest,
        policy_epoch: u64,
        context_version: u64,
    ) -> Self {
        Self {
            model_manifest_digest,
            protocol_schema_digest,
            policy_epoch,
            context_version,
        }
    }

    pub fn for_r1(
        model_manifest_digest: Digest,
        policy_epoch: u64,
        context_version: u64,
    ) -> Result<Self, RuntimeError> {
        Ok(Self::new(
            model_manifest_digest,
            canonical_digest("aeon-agent-protocol-schema-v1", &PROTOCOL_SCHEMA)?,
            policy_epoch,
            context_version,
        ))
    }

    pub fn resolve(
        &self,
        spec: &AgentSpec,
        registry: &ToolRegistry,
    ) -> Result<SemanticContext, RuntimeError> {
        if spec.semantic_requirements.requested_memory.is_some()
            || spec
                .semantic_requirements
                .requested_retrieval_index
                .is_some()
        {
            return Err(RuntimeError::new(
                ErrorCode::ContextResolutionFailed,
                "R1 has no trusted memory or retrieval generation registry",
            ));
        }
        let bound_tools = registry.resolve_all(&spec.requested_tools)?;
        let mut bound_tool_digests = bound_tools
            .iter()
            .map(|tool| tool.manifest_digest())
            .collect::<Result<Vec<_>, RuntimeError>>()?;
        bound_tool_digests.sort_unstable();
        bound_tool_digests.dedup();
        let instruction = resolved_system_instruction(spec)?;

        Ok(SemanticContext {
            context_version: self.context_version,
            model_manifest_digest: self.model_manifest_digest,
            resolved_system_instruction_digest: canonical_digest(
                "aeon-resolved-system-instruction-v1",
                &instruction,
            )?,
            tool_registry_root_digest: registry.root_digest()?,
            bound_tool_digests,
            protocol_schema_digest: self.protocol_schema_digest,
            policy_epoch: self.policy_epoch,
            memory_generation: None,
            retrieval_index_generation: None,
        })
    }
}

#[derive(Serialize)]
struct ResolvedInstruction<'a> {
    role: &'a crate::agent::Role,
    objective: &'a crate::agent::Objective,
    instruction_profile: &'a Option<crate::ids::InstructionProfileRef>,
    output_contract: &'a crate::agent::Contract,
}

pub fn resolved_system_instruction(spec: &AgentSpec) -> Result<String, RuntimeError> {
    serde_json::to_string(&ResolvedInstruction {
        role: &spec.role,
        objective: &spec.objective,
        instruction_profile: &spec.semantic_requirements.requested_instruction_profile,
        output_contract: &spec.output_contract,
    })
    .map_err(|error| {
        RuntimeError::new(
            ErrorCode::ContextResolutionFailed,
            format!("resolved instruction serialization failed: {error}"),
        )
    })
}
