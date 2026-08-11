use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use chrono::{Duration, Utc};
use nexus::Capability;
use serde_json::json;
use tokio::sync::Barrier;

use super::*;
use crate::{
    canonical_digest, AgentSpec, AuthorityRequest, Contract, Digest, EffectClass,
    InstructionProfileRef, MissionId, ModelRef, ModelResponse, Objective, RegisteredTool,
    ResourceRequest, Role, SemanticRequirements, ToolId,
};

#[derive(Debug)]
struct TestModel {
    responses: Mutex<VecDeque<String>>,
}

impl TestModel {
    fn new(responses: impl IntoIterator<Item = String>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
        }
    }
}

#[async_trait]
impl ModelClient for TestModel {
    async fn generate(&self, _request: ModelRequest) -> Result<ModelResponse, RuntimeError> {
        let raw_output = self
            .responses
            .lock()
            .map_err(|_| RuntimeError::new(ErrorCode::Internal, "test model lock poisoned"))?
            .pop_front()
            .ok_or_else(|| RuntimeError::new(ErrorCode::ModelFailed, "no scripted response"))?;
        Ok(ModelResponse { raw_output })
    }

    fn manifest_digest(&self, requested_model: &ModelRef) -> Result<Digest, RuntimeError> {
        canonical_digest("aeon-test-model-manifest-v1", requested_model)
    }
}

fn runtime_with_model(model: Arc<dyn ModelClient>) -> R1Runtime {
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
        model,
        ToolRegistry::from_tools(vec![tool]).unwrap(),
        1,
    )
    .unwrap()
}

fn runtime() -> R1Runtime {
    runtime_with_model(Arc::new(TestModel::new([json!({
        "kind": "final",
        "result": "done"
    })
    .to_string()])))
}

#[derive(Debug)]
struct BarrierFinalModel {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[async_trait]
impl ModelClient for BarrierFinalModel {
    async fn generate(&self, _request: ModelRequest) -> Result<ModelResponse, RuntimeError> {
        self.entered.wait().await;
        self.release.wait().await;
        Ok(ModelResponse {
            raw_output: json!({"kind": "final", "result": "done"}).to_string(),
        })
    }

    fn manifest_digest(&self, requested_model: &ModelRef) -> Result<Digest, RuntimeError> {
        canonical_digest("aeon-scripted-model-manifest-v1", requested_model)
    }
}

struct BarrierFinalFixture {
    runtime: Arc<R1Runtime>,
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[derive(Debug)]
struct FailingModel;

#[async_trait]
impl ModelClient for FailingModel {
    async fn generate(&self, _request: ModelRequest) -> Result<ModelResponse, RuntimeError> {
        Err(RuntimeError::new(
            ErrorCode::ModelFailed,
            "deterministic model failure",
        ))
    }

    fn manifest_digest(&self, requested_model: &ModelRef) -> Result<Digest, RuntimeError> {
        canonical_digest("aeon-scripted-model-manifest-v1", requested_model)
    }
}

#[derive(Debug)]
struct PanicManifestModel;

#[async_trait]
impl ModelClient for PanicManifestModel {
    async fn generate(&self, _request: ModelRequest) -> Result<ModelResponse, RuntimeError> {
        panic!("model generation must not run during bootstrap")
    }

    fn manifest_digest(&self, _requested_model: &ModelRef) -> Result<Digest, RuntimeError> {
        panic!("model manifest lookup must follow AgentSpec validation")
    }
}

impl BarrierFinalFixture {
    fn new() -> Self {
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let model = Arc::new(BarrierFinalModel {
            entered: entered.clone(),
            release: release.clone(),
        });
        Self {
            runtime: Arc::new(runtime_with_model(model)),
            entered,
            release,
        }
    }

    async fn start(&self) -> tokio::task::JoinHandle<Result<RunOutcome, RuntimeError>> {
        let runtime = self.runtime.clone();
        let task = tokio::spawn(async move { runtime.run_once().await });
        tokio::time::timeout(StdDuration::from_secs(2), self.entered.wait())
            .await
            .expect("model did not signal generation start");
        task
    }

    async fn release(&self) {
        tokio::time::timeout(StdDuration::from_secs(2), self.release.wait())
            .await
            .expect("model release timed out");
    }

    async fn finish(
        task: tokio::task::JoinHandle<Result<RunOutcome, RuntimeError>>,
    ) -> Result<RunOutcome, RuntimeError> {
        tokio::time::timeout(StdDuration::from_secs(2), task)
            .await
            .expect("runtime task timed out")
            .expect("runtime task panicked")
    }

    fn assert_rejected(&self, error: &RuntimeError, expected: ErrorCode) {
        assert_eq!(error.code(), expected);
        assert!(!self
            .runtime
            .event_kinds()
            .unwrap()
            .iter()
            .any(|kind| matches!(kind, MissionEventKind::FinalProduced)));
        assert!(self.runtime.event_kinds().unwrap().iter().any(|kind| {
            matches!(kind, MissionEventKind::FinalRejected(code) if *code == expected)
        }));
        assert_eq!(self.runtime.metrics().token_issues, 0);
        assert_eq!(self.runtime.metrics().nexus_executions, 0);
        self.runtime.verify_event_completeness().unwrap();
    }
}

#[test]
fn snapshot_accessors_return_successful_results() {
    let runtime = runtime();

    assert!(runtime.authorization_certificates().unwrap().is_empty());
    assert!(!runtime.authority_events().unwrap().is_empty());
}

#[test]
fn bootstrap_validates_agent_spec_before_registry_or_model_resolution() {
    let tool_id = ToolId::new("fixture.duplicate").unwrap();
    let error = R1Runtime::bootstrap(
        MissionEnvelope {
            mission_id: MissionId::new("mission-invalid-spec").unwrap(),
            allowed_tools: vec![tool_id.clone()],
            allowed_capabilities: vec![],
            policy_epoch: 1,
            organization_version: 1,
            active: true,
            expires_at: Utc::now() + Duration::minutes(10),
            max_actions: 1,
        },
        AgentId::new("agent-invalid-spec").unwrap(),
        AgentSpec {
            role: Role::new("invalid spec tester").unwrap(),
            objective: Objective::new("prove validation ordering").unwrap(),
            requested_model: ModelRef::new("model.must-not-resolve").unwrap(),
            requested_tools: vec![tool_id.clone(), tool_id],
            requested_authority: AuthorityRequest {
                capabilities: vec![],
            },
            output_contract: Contract::new("typed-agent-message-v1").unwrap(),
            resource_budget: ResourceRequest { max_steps: 1 },
            semantic_requirements: SemanticRequirements {
                requested_memory: None,
                requested_retrieval_index: None,
                requested_instruction_profile: None,
            },
        },
        Arc::new(PanicManifestModel),
        ToolRegistry::from_tools(vec![]).unwrap(),
        1,
    )
    .unwrap_err();

    assert_eq!(error.code(), ErrorCode::DuplicateTool);
}

#[test]
fn tool_free_runtime_renews_with_a_refreshed_empty_manifest() {
    let runtime = R1Runtime::bootstrap(
        MissionEnvelope {
            mission_id: MissionId::new("mission-tool-free-renewal").unwrap(),
            allowed_tools: vec![],
            allowed_capabilities: vec![],
            policy_epoch: 1,
            organization_version: 1,
            active: true,
            expires_at: Utc::now() + Duration::minutes(10),
            max_actions: 1,
        },
        AgentId::new("agent-tool-free-renewal").unwrap(),
        AgentSpec {
            role: Role::new("tool free agent").unwrap(),
            objective: Objective::new("renew without tool bindings").unwrap(),
            requested_model: ModelRef::new("model.fixture-v1").unwrap(),
            requested_tools: vec![],
            requested_authority: AuthorityRequest {
                capabilities: vec![],
            },
            output_contract: Contract::new("typed-agent-message-v1").unwrap(),
            resource_budget: ResourceRequest { max_steps: 1 },
            semantic_requirements: SemanticRequirements {
                requested_memory: None,
                requested_retrieval_index: None,
                requested_instruction_profile: None,
            },
        },
        Arc::new(TestModel::new([json!({
            "kind": "final",
            "result": "done"
        })
        .to_string()])),
        ToolRegistry::from_tools(vec![]).unwrap(),
        1,
    )
    .unwrap();
    let original = runtime.active_lease_snapshot().unwrap();

    let renewed = runtime.renew(Utc::now() + Duration::minutes(4)).unwrap();

    assert_ne!(renewed.certificate.lease_id, original.certificate.lease_id);
    assert!(renewed.manifest.approved_tools.is_empty());
    assert_eq!(
        renewed.manifest.tool_registry_root_digest,
        runtime
            .semantic_context()
            .unwrap()
            .tool_registry_root_digest
    );
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

#[test]
fn mission_evidence_snapshot_reports_poison_as_internal() {
    let runtime = runtime();
    let panic = catch_unwind(AssertUnwindSafe(|| {
        runtime.store.poison_events_for_test();
    }));
    assert!(panic.is_err());

    let error = runtime.event_kinds().unwrap_err();
    assert_eq!(error.code(), ErrorCode::Internal);
    let completeness_error = runtime.verify_event_completeness().unwrap_err();
    assert_eq!(completeness_error.code(), ErrorCode::Internal);
}

#[tokio::test]
async fn certificate_ledger_failure_is_a_complete_pre_nexus_rejection() {
    let runtime = runtime_with_model(Arc::new(TestModel::new([json!({
        "kind": "tool_call",
        "tool_id": "fixture.ledger",
        "arguments": {}
    })
    .to_string()])));
    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _guard = runtime.action_certificates.lock().unwrap();
        panic!("poison certificate ledger");
    }));
    assert!(panic.is_err());

    let error = runtime.run_once().await.unwrap_err();

    assert_eq!(error.code(), ErrorCode::Internal);
    assert!(runtime.event_kinds().unwrap().iter().any(|kind| {
        matches!(
            kind,
            MissionEventKind::ExecutionRejectedBeforeNexus(ErrorCode::Internal)
        )
    }));
    assert_eq!(runtime.metrics().token_issues, 0);
    assert_eq!(runtime.metrics().nexus_executions, 0);
    runtime.verify_event_completeness().unwrap();
}

#[tokio::test]
async fn consumed_authorization_without_consumption_evidence_is_incomplete() {
    let runtime = runtime_with_model(Arc::new(TestModel::new([json!({
        "kind": "tool_call",
        "tool_id": "fixture.ledger",
        "arguments": {}
    })
    .to_string()])));
    runtime.store.fail_authorization_consumed_append_for_test();

    let error = runtime.run_once().await.unwrap_err();

    assert_eq!(error.code(), ErrorCode::Internal);
    assert_eq!(runtime.metrics().token_issues, 1);
    assert_eq!(runtime.metrics().nexus_executions, 0);
    assert_eq!(
        runtime.authorization_records().unwrap()[0].state,
        crate::AuthorizationState::Consumed
    );
    assert!(!runtime.event_kinds().unwrap().iter().any(|kind| {
        matches!(
            kind,
            MissionEventKind::AuthorizationConsumed | MissionEventKind::ExecutionStarted
        )
    }));
    let completeness_error = runtime.verify_event_completeness().unwrap_err();
    assert_eq!(completeness_error.code(), ErrorCode::EventIncomplete);
}

#[tokio::test]
async fn final_generated_under_unchanged_live_authority_is_accepted() {
    let fixture = BarrierFinalFixture::new();
    let task = fixture.start().await;
    fixture.release().await;

    assert!(matches!(
        BarrierFinalFixture::finish(task).await.unwrap(),
        RunOutcome::Final(_)
    ));
    assert!(fixture
        .runtime
        .event_kinds()
        .unwrap()
        .iter()
        .any(|kind| matches!(kind, MissionEventKind::FinalProduced)));
    fixture.runtime.verify_event_completeness().unwrap();
}

#[tokio::test]
async fn model_failure_is_a_complete_terminal_attempt() {
    let runtime = runtime_with_model(Arc::new(FailingModel));

    let error = runtime.run_once().await.unwrap_err();

    assert_eq!(error.code(), ErrorCode::ModelFailed);
    assert!(runtime
        .event_kinds()
        .unwrap()
        .iter()
        .any(|kind| matches!(kind, MissionEventKind::ModelFailed(ErrorCode::ModelFailed))));
    runtime.verify_event_completeness().unwrap();
}

#[tokio::test]
async fn final_is_rejected_when_lease_is_paused_during_generation() {
    let fixture = BarrierFinalFixture::new();
    let task = fixture.start().await;
    fixture.runtime.pause().unwrap();
    fixture.release().await;

    let error = BarrierFinalFixture::finish(task).await.unwrap_err();
    fixture.assert_rejected(&error, ErrorCode::LeaseGenerationMismatch);
}

#[tokio::test]
async fn final_is_rejected_when_lease_is_revoked_during_generation() {
    let fixture = BarrierFinalFixture::new();
    let task = fixture.start().await;
    fixture.runtime.revoke("final-output test").unwrap();
    fixture.release().await;

    let error = BarrierFinalFixture::finish(task).await.unwrap_err();
    fixture.assert_rejected(&error, ErrorCode::LeaseGenerationMismatch);
}

#[tokio::test]
async fn final_is_rejected_when_lease_expires_during_generation() {
    let fixture = BarrierFinalFixture::new();
    let task = fixture.start().await;
    let active = fixture.runtime.active_lease_snapshot().unwrap();
    fixture
        .runtime
        .authority_kernel
        .refresh_expirations(active.certificate.expires_at)
        .unwrap();
    fixture.release().await;

    let error = BarrierFinalFixture::finish(task).await.unwrap_err();
    fixture.assert_rejected(&error, ErrorCode::LeaseGenerationMismatch);
}

#[tokio::test]
async fn final_is_rejected_when_lease_is_renewed_during_generation() {
    let fixture = BarrierFinalFixture::new();
    let task = fixture.start().await;
    fixture
        .runtime
        .renew(Utc::now() + Duration::minutes(4))
        .unwrap();
    fixture.release().await;

    let error = BarrierFinalFixture::finish(task).await.unwrap_err();
    fixture.assert_rejected(&error, ErrorCode::LeaseGenerationMismatch);
}

#[tokio::test]
async fn final_is_rejected_after_pause_resume_generation_aba() {
    let fixture = BarrierFinalFixture::new();
    let task = fixture.start().await;
    fixture.runtime.pause().unwrap();
    fixture.runtime.resume().unwrap();
    fixture.release().await;

    let error = BarrierFinalFixture::finish(task).await.unwrap_err();
    fixture.assert_rejected(&error, ErrorCode::LeaseGenerationMismatch);
}

#[tokio::test]
async fn final_is_rejected_when_material_context_changes_during_generation() {
    let fixture = BarrierFinalFixture::new();
    let task = fixture.start().await;
    let mut context = fixture.runtime.semantic_context().unwrap();
    context.policy_epoch += 1;
    fixture
        .runtime
        .replace_semantic_context_for_test(context)
        .unwrap();
    fixture.release().await;

    let error = BarrierFinalFixture::finish(task).await.unwrap_err();
    fixture.assert_rejected(&error, ErrorCode::SemanticContextChanged);
}

#[tokio::test]
async fn final_accepts_metadata_only_context_version_change_during_generation() {
    let fixture = BarrierFinalFixture::new();
    let task = fixture.start().await;
    let mut context = fixture.runtime.semantic_context().unwrap();
    context.context_version += 1;
    fixture
        .runtime
        .replace_semantic_context_for_test(context)
        .unwrap();
    fixture.release().await;

    assert!(matches!(
        BarrierFinalFixture::finish(task).await.unwrap(),
        RunOutcome::Final(_)
    ));
    fixture.runtime.verify_event_completeness().unwrap();
}
