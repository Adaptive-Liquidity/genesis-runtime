use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, Utc};
use nexus::Capability;
use serde_json::json;
use tokio::sync::Barrier;

use super::*;
use crate::{
    canonical_digest, AgentSpec, AuthorityRequest, Contract, Digest, EffectClass,
    InstructionProfileRef, MissionId, ModelRef, ModelResponse, Objective, ResourceRequest, Role,
    ScriptedModelClient, SemanticRequirements, ToolId,
};

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
    runtime_with_model(Arc::new(ScriptedModelClient::new([json!({
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
        self.entered.wait().await;
        task
    }

    async fn release(&self) {
        self.release.wait().await;
    }

    fn assert_rejected(&self, error: &RuntimeError, expected: ErrorCode) {
        assert_eq!(error.code(), expected);
        assert!(!self
            .runtime
            .event_kinds()
            .iter()
            .any(|kind| matches!(kind, MissionEventKind::FinalProduced)));
        assert!(self.runtime.event_kinds().iter().any(|kind| {
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

#[tokio::test]
async fn certificate_ledger_failure_is_a_complete_pre_nexus_rejection() {
    let runtime = runtime_with_model(Arc::new(ScriptedModelClient::new([json!({
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
    assert!(runtime.event_kinds().iter().any(|kind| {
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
async fn final_generated_under_unchanged_live_authority_is_accepted() {
    let fixture = BarrierFinalFixture::new();
    let task = fixture.start().await;
    fixture.release().await;

    assert!(matches!(task.await.unwrap().unwrap(), RunOutcome::Final(_)));
    assert!(fixture
        .runtime
        .event_kinds()
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

    let error = task.await.unwrap().unwrap_err();
    fixture.assert_rejected(&error, ErrorCode::LeaseGenerationMismatch);
}

#[tokio::test]
async fn final_is_rejected_when_lease_is_revoked_during_generation() {
    let fixture = BarrierFinalFixture::new();
    let task = fixture.start().await;
    fixture.runtime.revoke("final-output test").unwrap();
    fixture.release().await;

    let error = task.await.unwrap().unwrap_err();
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

    let error = task.await.unwrap().unwrap_err();
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

    let error = task.await.unwrap().unwrap_err();
    fixture.assert_rejected(&error, ErrorCode::LeaseGenerationMismatch);
}

#[tokio::test]
async fn final_is_rejected_after_pause_resume_generation_aba() {
    let fixture = BarrierFinalFixture::new();
    let task = fixture.start().await;
    fixture.runtime.pause().unwrap();
    fixture.runtime.resume().unwrap();
    fixture.release().await;

    let error = task.await.unwrap().unwrap_err();
    fixture.assert_rejected(&error, ErrorCode::LeaseGenerationMismatch);
}

#[tokio::test]
async fn final_is_rejected_when_material_context_changes_during_generation() {
    let fixture = BarrierFinalFixture::new();
    let task = fixture.start().await;
    let mut context = fixture.runtime.semantic_context();
    context.policy_epoch += 1;
    fixture.runtime.replace_semantic_context(context).unwrap();
    fixture.release().await;

    let error = task.await.unwrap().unwrap_err();
    fixture.assert_rejected(&error, ErrorCode::SemanticContextChanged);
}

#[tokio::test]
async fn final_accepts_metadata_only_context_version_change_during_generation() {
    let fixture = BarrierFinalFixture::new();
    let task = fixture.start().await;
    let mut context = fixture.runtime.semantic_context();
    context.context_version += 1;
    fixture.runtime.replace_semantic_context(context).unwrap();
    fixture.release().await;

    assert!(matches!(task.await.unwrap().unwrap(), RunOutcome::Final(_)));
    fixture.runtime.verify_event_completeness().unwrap();
}
