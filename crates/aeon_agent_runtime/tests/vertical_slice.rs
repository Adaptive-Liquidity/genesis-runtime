use std::sync::Arc;

mod common;

use aeon_agent_runtime::{
    AgentId, AgentSpec, AuthorityEventKind, AuthorityRequest, Contract, EffectClass, ErrorCode,
    InstructionProfileRef, MemoryRef, MissionEnvelope, MissionEventKind, MissionId, ModelRef,
    Objective, R1Runtime, R2Runtime, RegisteredTool, ResourceRequest, RetrievalIndexRef, Role,
    RunOutcome, SemanticRequirements, ToolId, ToolRegistry,
};
use chrono::{Duration, Utc};
use common::ScriptedModelClient;
use nexus::Capability;
use serde_json::json;

const FIXTURE_TOOL_ID: &str = "fixture.echo";

fn tool_id(value: &str) -> ToolId {
    ToolId::new(value).unwrap()
}

fn fixture_wasm(marker: i32) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(module
            (memory (export "memory") 1)
            (global i32 (i32.const {marker}))
            (func (export "_start")))"#
    ))
    .unwrap()
}

fn fixture_tool(id: &str, marker: i32, capabilities: Vec<Capability>) -> RegisteredTool {
    RegisteredTool::new(
        tool_id(id),
        fixture_wasm(marker),
        "_start",
        json!({
            "type": "object",
            "required": ["value"],
            "properties": {"value": {"type": "string"}},
            "additionalProperties": false
        }),
        capabilities,
        EffectClass::ReadOnly,
        None,
    )
    .unwrap()
}

fn trapping_fixture_tool(capabilities: Vec<Capability>) -> RegisteredTool {
    RegisteredTool::new(
        tool_id(FIXTURE_TOOL_ID),
        wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func (export "_start") unreachable))"#,
        )
        .unwrap(),
        "_start",
        json!({
            "type": "object",
            "required": ["value"],
            "properties": {"value": {"type": "string"}},
            "additionalProperties": false
        }),
        capabilities,
        EffectClass::ReadOnly,
        None,
    )
    .unwrap()
}

fn spec(authority: Vec<Capability>) -> AgentSpec {
    AgentSpec {
        role: Role::new("fixture operator").unwrap(),
        objective: Objective::new("execute one registered fixture").unwrap(),
        requested_model: ModelRef::new("model.fixture-v1").unwrap(),
        requested_tools: vec![tool_id(FIXTURE_TOOL_ID)],
        requested_authority: AuthorityRequest {
            capabilities: authority,
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
    }
}

fn mission(allowed_tools: Vec<&str>, authority: Vec<Capability>) -> MissionEnvelope {
    MissionEnvelope {
        mission_id: MissionId::new("mission-1").unwrap(),
        allowed_tools: allowed_tools.into_iter().map(tool_id).collect(),
        allowed_capabilities: authority,
        policy_epoch: 7,
        organization_version: 1,
        active: true,
        expires_at: Utc::now() + Duration::minutes(10),
        max_actions: 1,
    }
}

fn runtime(
    raw: &str,
    mission: MissionEnvelope,
    spec: AgentSpec,
    tools: Vec<RegisteredTool>,
) -> (R1Runtime, Arc<ScriptedModelClient>) {
    runtime_with_responses(vec![raw.to_owned()], mission, spec, tools)
}

fn runtime_with_responses(
    responses: Vec<String>,
    mission: MissionEnvelope,
    spec: AgentSpec,
    tools: Vec<RegisteredTool>,
) -> (R1Runtime, Arc<ScriptedModelClient>) {
    let model = Arc::new(ScriptedModelClient::new(responses));
    let registry = ToolRegistry::from_tools(tools).unwrap();
    let runtime = R1Runtime::bootstrap(
        mission,
        AgentId::new("agent-1").unwrap(),
        spec,
        model.clone(),
        registry,
        1,
    )
    .unwrap();
    (runtime, model)
}

fn tool_call(id: &str) -> String {
    json!({"kind":"tool_call","tool_id":id,"arguments":{"value":"hello"}}).to_string()
}

#[tokio::test]
async fn valid_typed_proposal_reaches_real_nexus() {
    let cap = Capability::MemoryPreview;
    let raw = tool_call(FIXTURE_TOOL_ID);
    let (runtime, _) = runtime(
        &raw,
        mission(vec![FIXTURE_TOOL_ID], vec![cap.clone()]),
        spec(vec![cap.clone()]),
        vec![fixture_tool(FIXTURE_TOOL_ID, 1, vec![cap])],
    );

    let outcome = runtime.run_once().await.unwrap();
    match outcome {
        RunOutcome::Executed(output) => assert!(output.success, "{output:?}"),
        other => panic!("expected real Nexus execution, got {other:?}"),
    }
    let metrics = runtime.metrics();
    assert_eq!(
        (
            metrics.model_calls,
            metrics.protocol_gate_calls,
            metrics.action_gate_calls,
            metrics.execution_port_calls,
            metrics.token_issues,
            metrics.nexus_executions,
        ),
        (1, 1, 1, 1, 1, 1)
    );
    assert_eq!(runtime.authorization_count().unwrap(), 1);
    assert_eq!(
        runtime.event_kinds().unwrap(),
        vec![
            MissionEventKind::MissionCreated,
            MissionEventKind::ContextResolved,
            MissionEventKind::LeaseIssued,
            MissionEventKind::AgentActivated,
            MissionEventKind::ProtocolAccepted,
            MissionEventKind::PlanAccepted,
            MissionEventKind::ActionAuthorized,
            MissionEventKind::AuthorizationIssued,
            MissionEventKind::AuthorizationConsumed,
            MissionEventKind::ExecutionStarted,
            MissionEventKind::ExecutionCompleted,
        ]
    );
    runtime.verify_event_completeness().unwrap();
}

#[tokio::test]
async fn multi_run_event_histories_are_complete_per_attempt() {
    let capability = Capability::MemoryPreview;
    let success = tool_call(FIXTURE_TOOL_ID);
    let action_rejected = tool_call("fixture.unknown");

    let cases = [
        vec![success.clone(), "not-json".to_owned()],
        vec!["not-json".to_owned(), success.clone()],
        vec![success.clone(), action_rejected.clone()],
        vec![action_rejected, success.clone()],
        vec![success.clone(), success],
    ];

    for (case_index, responses) in cases.into_iter().enumerate() {
        let mut case_mission = mission(vec![FIXTURE_TOOL_ID], vec![capability.clone()]);
        case_mission.max_actions = 2;
        let mut case_spec = spec(vec![capability.clone()]);
        case_spec.resource_budget.max_steps = responses.len() as u64;
        let (runtime, _) = runtime_with_responses(
            responses,
            case_mission,
            case_spec,
            vec![fixture_tool(
                FIXTURE_TOOL_ID,
                case_index as i32 + 1,
                vec![capability.clone()],
            )],
        );

        let first = runtime.run_once().await;
        let second = runtime.run_once().await;
        match case_index {
            0 => {
                assert!(matches!(first.unwrap(), RunOutcome::Executed(_)));
                assert_eq!(second.unwrap_err().code(), ErrorCode::MalformedProtocol);
            }
            1 => {
                assert_eq!(first.unwrap_err().code(), ErrorCode::MalformedProtocol);
                assert!(matches!(second.unwrap(), RunOutcome::Executed(_)));
            }
            2 => {
                assert!(matches!(first.unwrap(), RunOutcome::Executed(_)));
                assert_eq!(second.unwrap_err().code(), ErrorCode::ToolOutsideMission);
            }
            3 => {
                assert_eq!(first.unwrap_err().code(), ErrorCode::ToolOutsideMission);
                assert!(matches!(second.unwrap(), RunOutcome::Executed(_)));
            }
            4 => {
                assert!(matches!(first.unwrap(), RunOutcome::Executed(_)));
                assert!(matches!(second.unwrap(), RunOutcome::Executed(_)));
            }
            _ => unreachable!(),
        }
        runtime.verify_event_completeness().unwrap();
    }
}

#[tokio::test]
async fn malformed_output_stops_before_action_gate_and_nexus() {
    let cap = Capability::MemoryPreview;
    let (runtime, _) = runtime(
        "not-json",
        mission(vec![FIXTURE_TOOL_ID], vec![cap.clone()]),
        spec(vec![cap.clone()]),
        vec![fixture_tool(FIXTURE_TOOL_ID, 1, vec![cap])],
    );
    let error = runtime.run_once().await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedProtocol);
    let metrics = runtime.metrics();
    assert_eq!(
        (metrics.action_gate_calls, metrics.nexus_executions),
        (0, 0)
    );
    assert!(runtime
        .event_kinds()
        .unwrap()
        .contains(&MissionEventKind::ProtocolRejected(
            ErrorCode::MalformedProtocol
        )));
    assert!(!runtime
        .event_kinds()
        .unwrap()
        .contains(&MissionEventKind::ExecutionCompleted));
    runtime.verify_event_completeness().unwrap();
}

#[tokio::test]
async fn unknown_tool_stops_before_execution() {
    let cap = Capability::MemoryPreview;
    let raw = tool_call("fixture.missing");
    let (runtime, _) = runtime(
        &raw,
        mission(vec![FIXTURE_TOOL_ID, "fixture.missing"], vec![cap.clone()]),
        spec(vec![cap.clone()]),
        vec![fixture_tool(FIXTURE_TOOL_ID, 1, vec![cap])],
    );
    let error = runtime.run_once().await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnknownTool);
    assert_eq!(runtime.metrics().nexus_executions, 0);
}

#[tokio::test]
async fn known_tool_outside_allowlist_stops_before_execution() {
    let cap = Capability::MemoryPreview;
    let raw = tool_call("fixture.alt");
    let (runtime, _) = runtime(
        &raw,
        mission(vec![FIXTURE_TOOL_ID], vec![cap.clone()]),
        spec(vec![cap.clone()]),
        vec![
            fixture_tool(FIXTURE_TOOL_ID, 1, vec![cap.clone()]),
            fixture_tool("fixture.alt", 2, vec![cap]),
        ],
    );
    let error = runtime.run_once().await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::ToolOutsideMission);
    assert_eq!(runtime.metrics().nexus_executions, 0);
}

#[tokio::test]
async fn required_capability_outside_mission_authority_stops() {
    let raw = tool_call(FIXTURE_TOOL_ID);
    let (runtime, _) = runtime(
        &raw,
        mission(vec![FIXTURE_TOOL_ID], vec![Capability::MemoryPreview]),
        spec(vec![Capability::MemoryPreview]),
        vec![fixture_tool(
            FIXTURE_TOOL_ID,
            1,
            vec![Capability::ReadFile("/data".into())],
        )],
    );
    let error = runtime.run_once().await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::CapabilityOutsideAuthority);
    assert_eq!(runtime.metrics().nexus_executions, 0);
}

#[test]
fn capability_all_is_rejected_before_activation() {
    let model = Arc::new(ScriptedModelClient::new([tool_call(FIXTURE_TOOL_ID)]));
    let registry = ToolRegistry::from_tools(vec![fixture_tool(
        FIXTURE_TOOL_ID,
        1,
        vec![Capability::MemoryPreview],
    )])
    .unwrap();
    let error = R1Runtime::bootstrap(
        mission(vec![FIXTURE_TOOL_ID], vec![Capability::All]),
        AgentId::new("agent-1").unwrap(),
        spec(vec![Capability::All]),
        model,
        registry,
        1,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CapabilityAllForbidden);
}

#[test]
fn zero_action_or_step_budget_is_rejected_before_activation() {
    let cap = Capability::MemoryPreview;
    let registry =
        ToolRegistry::from_tools(vec![fixture_tool(FIXTURE_TOOL_ID, 1, vec![cap.clone()])])
            .unwrap();
    let mut no_actions = mission(vec![FIXTURE_TOOL_ID], vec![cap.clone()]);
    no_actions.max_actions = 0;
    let error = R1Runtime::bootstrap(
        no_actions,
        AgentId::new("agent-1").unwrap(),
        spec(vec![cap.clone()]),
        Arc::new(ScriptedModelClient::new([tool_call(FIXTURE_TOOL_ID)])),
        registry.clone(),
        1,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::BudgetExhausted);

    let mut no_steps = spec(vec![cap.clone()]);
    no_steps.resource_budget.max_steps = 0;
    let error = R1Runtime::bootstrap(
        mission(vec![FIXTURE_TOOL_ID], vec![cap]),
        AgentId::new("agent-1").unwrap(),
        no_steps,
        Arc::new(ScriptedModelClient::new([tool_call(FIXTURE_TOOL_ID)])),
        registry,
        1,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::BudgetExhausted);
}

#[test]
fn requested_memory_fails_closed_without_a_trusted_generation_registry() {
    let cap = Capability::MemoryPreview;
    let mut memory_spec = spec(vec![cap.clone()]);
    memory_spec.semantic_requirements.requested_memory =
        Some(MemoryRef::new("memory.fixture-v1").unwrap());
    let error = R1Runtime::bootstrap(
        mission(vec![FIXTURE_TOOL_ID], vec![cap.clone()]),
        AgentId::new("agent-1").unwrap(),
        memory_spec,
        Arc::new(ScriptedModelClient::new([tool_call(FIXTURE_TOOL_ID)])),
        ToolRegistry::from_tools(vec![fixture_tool(FIXTURE_TOOL_ID, 1, vec![cap])]).unwrap(),
        1,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::ContextResolutionFailed);
}

#[test]
fn requested_retrieval_fails_closed_without_a_trusted_generation_registry() {
    let cap = Capability::MemoryPreview;
    let mut retrieval_spec = spec(vec![cap.clone()]);
    retrieval_spec
        .semantic_requirements
        .requested_retrieval_index = Some(RetrievalIndexRef::new("retrieval.fixture-v1").unwrap());
    let error = R1Runtime::bootstrap(
        mission(vec![FIXTURE_TOOL_ID], vec![cap.clone()]),
        AgentId::new("agent-1").unwrap(),
        retrieval_spec,
        Arc::new(ScriptedModelClient::new([tool_call(FIXTURE_TOOL_ID)])),
        ToolRegistry::from_tools(vec![fixture_tool(FIXTURE_TOOL_ID, 1, vec![cap])]).unwrap(),
        1,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::ContextResolutionFailed);
}

#[tokio::test]
async fn a_second_action_cannot_exceed_the_mission_budget() {
    let cap = Capability::MemoryPreview;
    let mut two_step_spec = spec(vec![cap.clone()]);
    two_step_spec.resource_budget.max_steps = 2;
    let raw = tool_call(FIXTURE_TOOL_ID);
    let model = Arc::new(ScriptedModelClient::new([raw.clone(), raw]));
    let runtime = R1Runtime::bootstrap(
        mission(vec![FIXTURE_TOOL_ID], vec![cap.clone()]),
        AgentId::new("agent-1").unwrap(),
        two_step_spec,
        model,
        ToolRegistry::from_tools(vec![fixture_tool(FIXTURE_TOOL_ID, 1, vec![cap])]).unwrap(),
        1,
    )
    .unwrap();

    assert!(matches!(
        runtime.run_once().await.unwrap(),
        RunOutcome::Executed(_)
    ));
    let error = runtime.run_once().await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::BudgetExhausted);
    assert_eq!(runtime.metrics().nexus_executions, 1);
    assert_eq!(runtime.metrics().token_issues, 1);
    assert_eq!(runtime.authorization_count().unwrap(), 1);
}

#[tokio::test]
async fn nexus_tool_failure_emits_a_terminal_execution_failure_event() {
    let cap = Capability::MemoryPreview;
    let raw = tool_call(FIXTURE_TOOL_ID);
    let (runtime, _) = runtime(
        &raw,
        mission(vec![FIXTURE_TOOL_ID], vec![cap.clone()]),
        spec(vec![cap.clone()]),
        vec![trapping_fixture_tool(vec![cap])],
    );

    let outcome = runtime.run_once().await.unwrap();
    match outcome {
        RunOutcome::Executed(output) => assert!(!output.success),
        other => panic!("expected a failed Nexus execution output, got {other:?}"),
    }
    assert!(runtime
        .event_kinds()
        .unwrap()
        .contains(&MissionEventKind::ExecutionFailed(
            ErrorCode::ExecutionFailed
        )));
    assert!(!runtime
        .event_kinds()
        .unwrap()
        .contains(&MissionEventKind::ExecutionCompleted));
    runtime.verify_event_completeness().unwrap();
}

#[tokio::test]
async fn registry_tool_requiring_all_is_rejected_at_action_gate() {
    let raw = tool_call(FIXTURE_TOOL_ID);
    let (runtime, _) = runtime(
        &raw,
        mission(vec![FIXTURE_TOOL_ID], vec![Capability::MemoryPreview]),
        spec(vec![Capability::MemoryPreview]),
        vec![fixture_tool(FIXTURE_TOOL_ID, 1, vec![Capability::All])],
    );
    let error = runtime.run_once().await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::CapabilityAllForbidden);
    assert_eq!(runtime.metrics().nexus_executions, 0);
}

#[tokio::test]
async fn model_facing_structures_never_receive_tokens_or_wasm() {
    let cap = Capability::MemoryPreview;
    let raw = tool_call(FIXTURE_TOOL_ID);
    let (runtime, model) = runtime(
        &raw,
        mission(vec![FIXTURE_TOOL_ID], vec![cap.clone()]),
        spec(vec![cap.clone()]),
        vec![fixture_tool(FIXTURE_TOOL_ID, 1, vec![cap])],
    );
    runtime.run_once().await.unwrap();
    let trace = serde_json::to_string(&model.trace())
        .unwrap()
        .to_ascii_lowercase();
    assert!(!trace.contains("capabilitytoken"));
    assert!(!trace.contains("capability_token"));
    assert!(!trace.contains("bearer"));
    assert!(!trace.contains("wasm_bytes"));
    assert_eq!(runtime.metrics().token_issues, 1);
}

#[tokio::test]
async fn r2_pause_before_run_rejects_without_issuing_tokens_or_entering_nexus() {
    let cap = Capability::MemoryPreview;
    let raw = tool_call(FIXTURE_TOOL_ID);
    let (runtime, _) = runtime(
        &raw,
        mission(vec![FIXTURE_TOOL_ID], vec![cap.clone()]),
        spec(vec![cap.clone()]),
        vec![fixture_tool(FIXTURE_TOOL_ID, 1, vec![cap])],
    );

    runtime.pause().unwrap();
    let error = runtime.run_once().await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::LeaseInactive);
    assert_eq!(
        (
            runtime.metrics().token_issues,
            runtime.metrics().nexus_executions
        ),
        (0, 0)
    );
    assert!(runtime
        .authority_events()
        .unwrap()
        .iter()
        .any(|event| event.kind == AuthorityEventKind::LeasePaused));
}

#[tokio::test]
async fn r2_revoke_before_run_rejects_without_issuing_tokens_or_entering_nexus() {
    let cap = Capability::MemoryPreview;
    let raw = tool_call(FIXTURE_TOOL_ID);
    let (runtime, _) = runtime(
        &raw,
        mission(vec![FIXTURE_TOOL_ID], vec![cap.clone()]),
        spec(vec![cap.clone()]),
        vec![fixture_tool(FIXTURE_TOOL_ID, 1, vec![cap])],
    );

    runtime.revoke("test principal revocation").unwrap();
    let error = runtime.run_once().await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::LeaseInactive);
    assert_eq!(
        (
            runtime.metrics().token_issues,
            runtime.metrics().nexus_executions
        ),
        (0, 0)
    );
    assert!(runtime
        .authority_events()
        .unwrap()
        .iter()
        .any(|event| event.kind == AuthorityEventKind::LeaseRevoked));
}

#[tokio::test]
async fn r2_renewal_switches_immutable_lease_and_new_lease_executes() {
    let cap = Capability::MemoryPreview;
    let raw = tool_call(FIXTURE_TOOL_ID);
    let (runtime, _) = runtime(
        &raw,
        mission(vec![FIXTURE_TOOL_ID], vec![cap.clone()]),
        spec(vec![cap.clone()]),
        vec![fixture_tool(FIXTURE_TOOL_ID, 1, vec![cap])],
    );
    let runtime: R2Runtime = runtime;
    let original = runtime.active_lease_snapshot().unwrap();

    let renewed = runtime.renew(Utc::now() + Duration::minutes(4)).unwrap();
    assert_ne!(renewed.certificate.lease_id, original.certificate.lease_id);
    assert_eq!(
        renewed
            .certificate
            .renewed_from
            .as_ref()
            .map(|reference| &reference.lease_id),
        Some(&original.certificate.lease_id)
    );
    let retired = runtime
        .lease_snapshot(&original.certificate.lease_id)
        .unwrap();
    assert_eq!(retired.certificate, original.certificate);
    assert_eq!(
        retired.record.state,
        aeon_agent_runtime::LeaseState::Retired
    );

    assert!(matches!(
        runtime.run_once().await.unwrap(),
        RunOutcome::Executed(_)
    ));
    assert_eq!(
        (
            runtime.metrics().token_issues,
            runtime.metrics().nexus_executions
        ),
        (1, 1)
    );
    assert!(runtime
        .authority_events()
        .unwrap()
        .iter()
        .any(|event| event.kind == AuthorityEventKind::LeaseRenewed));
}

#[test]
fn same_context_renewal_retains_the_original_semantic_binding() {
    let cap = Capability::MemoryPreview;
    let raw = tool_call(FIXTURE_TOOL_ID);
    let (runtime, _) = runtime(
        &raw,
        mission(vec![FIXTURE_TOOL_ID], vec![cap.clone()]),
        spec(vec![cap.clone()]),
        vec![fixture_tool(FIXTURE_TOOL_ID, 1, vec![cap])],
    );
    let original = runtime.active_lease_snapshot().unwrap();

    let renewed = runtime.renew(Utc::now() + Duration::minutes(4)).unwrap();

    assert_eq!(
        renewed.certificate.semantic_context_digest,
        original.certificate.semantic_context_digest
    );
}
