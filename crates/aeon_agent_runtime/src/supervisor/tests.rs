use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use chrono::{Duration, Utc};
use nexus::Capability;
use serde_json::json;

use super::*;
use crate::{
    AgentSpec, AuthorityRequest, Contract, EffectClass, InstructionProfileRef, MissionId, ModelRef,
    Objective, ResourceRequest, Role, ScriptedModelClient, SemanticRequirements, ToolId,
};

fn runtime() -> R1Runtime {
    let tool_id = ToolId::new("fixture.ledger").unwrap();
    let tool = RegisteredTool::new(
        tool_id.clone(),
        wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func (export "_start")))"#,
        )
        .unwrap(),
        "_start",
        json!({"type": "object", "additionalProperties": false}),
        vec![Capability::MemoryPreview],
        EffectClass::ReadOnly,
        None,
    )
    .unwrap();
    R1Runtime::bootstrap(
        MissionEnvelope {
            mission_id: MissionId::new("mission-ledger").unwrap(),
            allowed_tools: vec![tool_id.clone()],
            allowed_capabilities: vec![Capability::MemoryPreview],
            policy_epoch: 7,
            organization_version: 1,
            active: true,
            expires_at: Utc::now() + Duration::minutes(10),
            max_actions: 1,
        },
        AgentId::new("agent-ledger").unwrap(),
        AgentSpec {
            role: Role::new("ledger tester").unwrap(),
            objective: Objective::new("exercise runtime snapshots").unwrap(),
            requested_model: ModelRef::new("model.fixture-v1").unwrap(),
            requested_tools: vec![tool_id],
            requested_authority: AuthorityRequest {
                capabilities: vec![Capability::MemoryPreview],
            },
            output_contract: Contract::new("typed-agent-message-v1").unwrap(),
            resource_budget: ResourceRequest { max_steps: 1 },
            semantic_requirements: SemanticRequirements {
                requested_memory: None,
                requested_retrieval_index: None,
                requested_instruction_profile: Some(
                    InstructionProfileRef::new("profile.fixture-v1").unwrap(),
                ),
            },
        },
        Arc::new(ScriptedModelClient::new([json!({
            "kind": "final",
            "result": {"ok": true}
        })
        .to_string()])),
        ToolRegistry::from_tools(vec![tool]).unwrap(),
        1,
    )
    .unwrap()
}

#[test]
fn snapshot_accessors_return_successful_results() {
    let runtime = runtime();

    assert!(runtime.authorization_certificates().unwrap().is_empty());
    assert!(!runtime.authority_events().unwrap().is_empty());
}

#[test]
fn authorization_certificate_snapshot_reports_poison_as_internal() {
    let runtime = runtime();
    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _guard = runtime.action_certificates.lock().unwrap();
        panic!("poison certificate ledger");
    }));
    assert!(panic.is_err());

    let error = runtime.authorization_certificates().unwrap_err();
    assert_eq!(error.code(), ErrorCode::Internal);
}
