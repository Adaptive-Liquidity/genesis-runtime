use std::sync::Arc;

use aeon_agent_runtime::{
    AgentId, AgentSpec, AuthorityRequest, Contract, EffectClass, ErrorCode, InstructionProfileRef,
    MemoryRef, MissionEnvelope, MissionEventKind, MissionId, ModelRef, Objective, R1Runtime,
    RegisteredTool, ResourceRequest, RetrievalIndexRef, Role, RunOutcome, ScriptedModelClient,
    SemanticRequirements, ToolId, ToolRegistry,
};
use chrono::{Duration, Utc};
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
    let model = Arc::new(ScriptedModelClient::new([raw.to_owned()]));
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
    assert_eq!(runtime.authorization_count(), 1);
    assert_eq!(
        runtime.event_kinds(),
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
        .contains(&MissionEventKind::ProtocolRejected(
            ErrorCode::MalformedProtocol
        )));
    assert!(!runtime
        .event_kinds()
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
    assert_eq!(runtime.authorization_count(), 1);
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
        .contains(&MissionEventKind::ExecutionFailed(
            ErrorCode::ExecutionFailed
        )));
    assert!(!runtime
        .event_kinds()
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
async fn t8_registry_substitution_is_rejected_before_nexus() {
    let cap = Capability::MemoryPreview;
    let raw = tool_call(FIXTURE_TOOL_ID);
    let (runtime, _) = runtime(
        &raw,
        mission(vec![FIXTURE_TOOL_ID], vec![cap.clone()]),
        spec(vec![cap.clone()]),
        vec![fixture_tool(FIXTURE_TOOL_ID, 1, vec![cap.clone()])],
    );
    runtime
        .replace_registered_tool(fixture_tool(FIXTURE_TOOL_ID, 2, vec![cap]))
        .unwrap();
    let error = runtime.run_once().await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::ToolManifestMismatch);
    assert_eq!(runtime.metrics().nexus_executions, 0);
}

#[tokio::test]
async fn t11_metadata_version_change_is_exact_but_material_drift_rejects() {
    let cap = Capability::MemoryPreview;
    let raw = tool_call(FIXTURE_TOOL_ID);
    let (metadata_runtime, _) = runtime(
        &raw,
        mission(vec![FIXTURE_TOOL_ID], vec![cap.clone()]),
        spec(vec![cap.clone()]),
        vec![fixture_tool(FIXTURE_TOOL_ID, 1, vec![cap])],
    );
    let mut metadata_only = metadata_runtime.semantic_context();
    metadata_only.context_version += 1;
    metadata_runtime
        .replace_semantic_context(metadata_only)
        .unwrap();
    assert!(matches!(
        metadata_runtime.run_once().await.unwrap(),
        RunOutcome::Executed(_)
    ));

    let cap = Capability::MemoryPreview;
    let raw = tool_call(FIXTURE_TOOL_ID);
    let (drift_runtime, _) = runtime(
        &raw,
        mission(vec![FIXTURE_TOOL_ID], vec![cap.clone()]),
        spec(vec![cap.clone()]),
        vec![fixture_tool(FIXTURE_TOOL_ID, 1, vec![cap])],
    );
    let mut drifted = drift_runtime.semantic_context();
    drifted.policy_epoch += 1;
    drift_runtime.replace_semantic_context(drifted).unwrap();
    let error = drift_runtime.run_once().await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::SemanticContextChanged);
    assert_eq!(drift_runtime.metrics().nexus_executions, 0);
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
