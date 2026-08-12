use serde::Serialize;

use crate::agent::{AgentSpec, SemanticContext};
use crate::digest::{canonical_digest, Digest};
use crate::error::{ErrorCode, RuntimeError};
use crate::protocol::AgentMessage;
use crate::tool_registry::RegistrySnapshot;

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
            AgentMessage::schema_digest()?,
            policy_epoch,
            context_version,
        ))
    }

    pub(crate) fn resolve(
        &self,
        spec: &AgentSpec,
        registry_snapshot: &RegistrySnapshot,
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
        let mut bound_tool_digests = registry_snapshot
            .bound_tools()
            .iter()
            .map(|tool| tool.tool_manifest_digest)
            .collect::<Vec<_>>();
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
            tool_registry_root_digest: registry_snapshot.root_digest(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{Contract, Objective, ResourceRequest, Role, SemanticRequirements};
    use crate::authority::AuthorityRequest;
    use crate::ids::ModelRef;
    use crate::tool_registry::ToolRegistry;

    #[test]
    fn resolver_accepts_atomic_snapshot_with_no_requested_tools() {
        let spec = AgentSpec {
            role: Role::new("tester").expect("valid role"),
            objective: Objective::new("verify context").expect("valid objective"),
            requested_model: ModelRef::new("fixture.model").expect("valid model"),
            requested_tools: vec![],
            requested_authority: AuthorityRequest {
                capabilities: vec![],
            },
            output_contract: Contract::new("return a result").expect("valid contract"),
            resource_budget: ResourceRequest { max_steps: 1 },
            semantic_requirements: SemanticRequirements {
                requested_memory: None,
                requested_retrieval_index: None,
                requested_instruction_profile: None,
            },
        };
        let registry = ToolRegistry::from_tools(vec![]).expect("empty registry is valid");
        let snapshot = registry.snapshot(&[]).expect("empty snapshot resolves");
        let resolver = ContextResolver::new(Digest::new([1; 32]), Digest::new([2; 32]), 3, 4);

        let context = resolver
            .resolve(&spec, &snapshot)
            .expect("context resolves");

        assert!(context.bound_tool_digests.is_empty());
        assert_eq!(context.tool_registry_root_digest, snapshot.root_digest());
    }
}
