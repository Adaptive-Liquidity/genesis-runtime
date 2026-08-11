use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use nexus::{Capability, HypervisorConfig};
use serde_json::json;

use super::*;
use crate::{
    canonical_digest, AgentId, AuthoritySet, BoundTool, EffectClass, InMemoryKeyCustody,
    KeyCustody, KeyId, MissionEventKind, MissionId, PermissionSet, RegisteredTool, RenewalRequest,
    RootLeaseRequest,
};

const TOOL_ID: &str = "fixture.commit";

struct CommitFixture {
    mission: MissionEnvelope,
    agent_id: AgentId,
    registry: ToolRegistry,
    semantic_context: Arc<RwLock<SemanticContext>>,
    authority_kernel: AuthorityKernel,
    key_custody: Arc<InMemoryKeyCustody>,
    store: Arc<InMemoryMissionStore>,
    metrics: Arc<MetricCounters>,
    port: Arc<NexusExecutionPort>,
}

impl CommitFixture {
    fn new() -> Self {
        let now = Utc::now();
        let tool_id = ToolId::new(TOOL_ID).unwrap();
        let tool = registered_tool(1);
        let registry = ToolRegistry::from_tools(vec![tool.clone()]).unwrap();
        let model_manifest_digest = canonical_digest("test-model", &"model-v1").unwrap();
        let semantic_context = SemanticContext {
            context_version: 1,
            model_manifest_digest,
            resolved_system_instruction_digest: canonical_digest(
                "test-instruction",
                &"instruction-v1",
            )
            .unwrap(),
            tool_registry_root_digest: registry.root_digest().unwrap(),
            bound_tool_digests: vec![tool.manifest_digest().unwrap()],
            protocol_schema_digest: canonical_digest("test-protocol", &"protocol-v1").unwrap(),
            policy_epoch: 7,
            memory_generation: None,
            retrieval_index_generation: None,
        };
        let capability_manifest = CapabilityManifest {
            version: 1,
            model_manifest_digest,
            approved_tools: vec![BoundTool {
                tool_id: tool_id.clone(),
                tool_manifest_digest: tool.manifest_digest().unwrap(),
            }],
            permissions: PermissionSet {
                capabilities: vec![Capability::MemoryPreview],
            },
            runtime_config_digest: canonical_digest("test-runtime", &(1_u64, 1_u64)).unwrap(),
            tool_registry_root_digest: registry.root_digest().unwrap(),
        };
        let mission = MissionEnvelope {
            mission_id: MissionId::new("mission-commit").unwrap(),
            allowed_tools: vec![tool_id],
            allowed_capabilities: vec![Capability::MemoryPreview],
            policy_epoch: 7,
            organization_version: 1,
            active: true,
            expires_at: now + Duration::minutes(10),
            max_actions: 10,
        };
        let agent_id = AgentId::new("agent-commit").unwrap();
        let key_custody =
            Arc::new(InMemoryKeyCustody::generate(KeyId::new("key-commit").unwrap()).unwrap());
        let kernel_custody: Arc<dyn KeyCustody> = key_custody.clone();
        let authority_kernel = AuthorityKernel::bootstrap(
            RootLeaseRequest {
                mission: mission.clone(),
                agent_id: agent_id.clone(),
                granted_authority: AuthoritySet::new(vec![Capability::MemoryPreview]).unwrap(),
                delegable_authority: AuthoritySet::new(Vec::new()).unwrap(),
                capability_manifest,
                semantic_context_digest: semantic_context.canonical_digest().unwrap(),
                expires_at: now + Duration::minutes(5),
            },
            kernel_custody.clone(),
            now,
        )
        .unwrap();
        let semantic_context = Arc::new(RwLock::new(semantic_context));
        let store = Arc::new(InMemoryMissionStore::new(mission.clone()));
        let metrics = Arc::new(MetricCounters::default());
        let port = Arc::new(NexusExecutionPort::new(
            HypervisorConfig::default(),
            registry.clone(),
            authority_kernel.clone(),
            semantic_context.clone(),
            store.clone(),
            kernel_custody,
            metrics.clone(),
        ));
        Self {
            mission,
            agent_id,
            registry,
            semantic_context,
            authority_kernel,
            key_custody,
            store,
            metrics,
            port,
        }
    }

    fn authorize(&self) -> AuthorizedExecution {
        let lease_id = self.authority_kernel.root_lease_id().unwrap();
        let context = self.semantic_context.read().unwrap().clone();
        let (authorized, artifact) = ActionGate
            .authorize(
                &self.mission,
                &self.agent_id,
                &self.authority_kernel,
                &lease_id,
                &context,
                &self.registry,
                &ToolId::new(TOOL_ID).unwrap(),
                &json!({"value": "hello"}),
                self.key_custody.as_ref(),
                Utc::now(),
            )
            .unwrap();
        self.store.insert_authorization(artifact.record).unwrap();
        authorized
    }

    fn assert_no_nexus(&self) {
        assert_eq!(self.metrics.snapshot().nexus_executions, 0);
        assert_eq!(self.metrics.snapshot().token_issues, 0);
    }
}

fn registered_tool(marker: i32) -> RegisteredTool {
    let wasm = wat::parse_str(format!(
        r#"(module
            (memory (export "memory") 1)
            (global i32 (i32.const {marker}))
            (func (export "_start")))"#
    ))
    .unwrap();
    RegisteredTool::new(
        ToolId::new(TOOL_ID).unwrap(),
        wasm,
        "_start",
        json!({
            "type": "object",
            "required": ["value"],
            "properties": {"value": {"type": "string"}},
            "additionalProperties": false
        }),
        vec![Capability::MemoryPreview],
        EffectClass::ReadOnly,
        None,
    )
    .unwrap()
}

#[tokio::test]
async fn a_pause_after_authorize_rejects_before_nexus() {
    let fixture = CommitFixture::new();
    let authorized = fixture.authorize();
    let active = fixture
        .authority_kernel
        .lease_snapshot(&authorized.certificate.authority_lease_id)
        .unwrap();
    fixture
        .authority_kernel
        .pause(
            &active.certificate.lease_id,
            active.record.generation,
            Utc::now(),
        )
        .unwrap();

    let error = fixture.port.execute(authorized, 1).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::LeaseGenerationMismatch);
    fixture.assert_no_nexus();
}

#[tokio::test]
async fn b_pause_resume_after_authorize_rejects_stale_generation_before_nexus() {
    let fixture = CommitFixture::new();
    let authorized = fixture.authorize();
    let active = fixture
        .authority_kernel
        .lease_snapshot(&authorized.certificate.authority_lease_id)
        .unwrap();
    let paused = fixture
        .authority_kernel
        .pause(
            &active.certificate.lease_id,
            active.record.generation,
            Utc::now(),
        )
        .unwrap();
    fixture
        .authority_kernel
        .resume(&active.certificate.lease_id, paused.generation, Utc::now())
        .unwrap();

    let error = fixture.port.execute(authorized, 1).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::LeaseGenerationMismatch);
    fixture.assert_no_nexus();
}

#[tokio::test]
async fn c_revoke_after_authorize_rejects_before_nexus() {
    let fixture = CommitFixture::new();
    let authorized = fixture.authorize();
    let active = fixture
        .authority_kernel
        .lease_snapshot(&authorized.certificate.authority_lease_id)
        .unwrap();
    fixture
        .authority_kernel
        .revoke(
            &active.certificate.lease_id,
            active.record.generation,
            "test revocation",
            Utc::now(),
        )
        .unwrap();

    let error = fixture.port.execute(authorized, 1).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::LeaseGenerationMismatch);
    fixture.assert_no_nexus();
}

#[tokio::test]
async fn d_renew_after_authorize_rejects_retired_lease_before_nexus() {
    let fixture = CommitFixture::new();
    let authorized = fixture.authorize();
    let active = fixture
        .authority_kernel
        .lease_snapshot(&authorized.certificate.authority_lease_id)
        .unwrap();
    fixture
        .authority_kernel
        .renew(
            RenewalRequest {
                lease_id: active.certificate.lease_id,
                expected_generation: active.record.generation,
                granted_authority: active.certificate.granted_authority,
                delegable_authority: active.certificate.delegable_authority,
                capability_manifest: active.manifest,
                semantic_context_digest: authorized.certificate.semantic_context_digest,
                expires_at: Utc::now() + Duration::minutes(4),
            },
            Utc::now(),
        )
        .unwrap();

    let error = fixture.port.execute(authorized, 1).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::LeaseGenerationMismatch);
    fixture.assert_no_nexus();
}

#[tokio::test]
async fn e_semantic_drift_after_authorize_rejects_before_nexus() {
    let fixture = CommitFixture::new();
    let authorized = fixture.authorize();
    fixture.semantic_context.write().unwrap().policy_epoch += 1;

    let error = fixture.port.execute(authorized, 1).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::SemanticContextChanged);
    fixture.assert_no_nexus();
}

#[tokio::test]
async fn f_tool_substitution_after_authorize_rejects_before_nexus() {
    let fixture = CommitFixture::new();
    let authorized = fixture.authorize();
    fixture.registry.replace(registered_tool(2)).unwrap();

    let error = fixture.port.execute(authorized, 1).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::ToolManifestMismatch);
    fixture.assert_no_nexus();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g_barrier_synchronized_double_consumption_has_one_success_and_one_nexus_entry() {
    let fixture = CommitFixture::new();
    let authorized = fixture.authorize();
    let barrier = Arc::new(tokio::sync::Barrier::new(3));

    let first_port = fixture.port.clone();
    let first_authorized = authorized.clone();
    let first_barrier = barrier.clone();
    let first = tokio::spawn(async move {
        tokio::time::timeout(StdDuration::from_secs(2), first_barrier.wait())
            .await
            .expect("first execution barrier timed out");
        first_port.execute(first_authorized, 1).await
    });
    let second_port = fixture.port.clone();
    let second_barrier = barrier.clone();
    let second = tokio::spawn(async move {
        tokio::time::timeout(StdDuration::from_secs(2), second_barrier.wait())
            .await
            .expect("second execution barrier timed out");
        second_port.execute(authorized, 1).await
    });
    tokio::time::timeout(StdDuration::from_secs(2), barrier.wait())
        .await
        .expect("coordinator barrier timed out");

    let results = [
        tokio::time::timeout(StdDuration::from_secs(2), first)
            .await
            .expect("first execution timed out")
            .unwrap(),
        tokio::time::timeout(StdDuration::from_secs(2), second)
            .await
            .expect("second execution timed out")
            .unwrap(),
    ];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .filter(|error| error.code() == ErrorCode::AuthorizationInvalid)
            .count(),
        1
    );
    let metrics = fixture.metrics.snapshot();
    assert_eq!(metrics.token_issues, 1);
    assert_eq!(metrics.nexus_executions, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h_commit_first_revoke_blocks_then_future_execution_rejects() {
    let fixture = CommitFixture::new();
    let authorized = fixture.authorize();
    let active = fixture
        .authority_kernel
        .lease_snapshot(&authorized.certificate.authority_lease_id)
        .unwrap();
    let (consumed_tx, consumed_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Arc::new(Mutex::new(release_rx));
    let port = fixture.port.clone();
    let first_authorized = authorized.clone();
    let execution = tokio::spawn(async move {
        port.execute_with_test_hooks(
            first_authorized,
            1,
            ExecutionTestHooks {
                after_authorization_consumed_under_guard: Some(Arc::new(move || {
                    consumed_tx.send(()).unwrap();
                    release_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(StdDuration::from_secs(2))
                        .expect("commit cutpoint release timed out");
                })),
            },
        )
        .await
    });
    consumed_rx
        .recv_timeout(StdDuration::from_secs(2))
        .expect("execution did not reach the authorization-consumed cutpoint");

    let kernel = fixture.authority_kernel.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (revoked_tx, revoked_rx) = mpsc::channel();
    let revocation = tokio::task::spawn_blocking(move || {
        started_tx.send(()).unwrap();
        let result = kernel.revoke(
            &active.certificate.lease_id,
            active.record.generation,
            "commit-first test",
            Utc::now(),
        );
        revoked_tx.send(()).unwrap();
        result
    });
    started_rx
        .recv_timeout(StdDuration::from_secs(2))
        .expect("revocation thread did not start");
    assert!(revoked_rx
        .recv_timeout(StdDuration::from_millis(100))
        .is_err());

    release_tx.send(()).unwrap();
    assert!(tokio::time::timeout(StdDuration::from_secs(2), execution)
        .await
        .expect("execution timed out")
        .unwrap()
        .is_ok());
    tokio::time::timeout(StdDuration::from_secs(2), revocation)
        .await
        .expect("revocation timed out")
        .unwrap()
        .unwrap();
    let committed_metrics = fixture.metrics.snapshot();
    assert_eq!(committed_metrics.token_issues, 1);
    assert_eq!(committed_metrics.nexus_executions, 1);

    let error = fixture.port.execute(authorized, 2).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::LeaseGenerationMismatch);
    let rejected_metrics = fixture.metrics.snapshot();
    assert_eq!(rejected_metrics.token_issues, 1);
    assert_eq!(rejected_metrics.nexus_executions, 1);
}

#[tokio::test]
async fn i_authorization_consumed_evidence_failure_is_fail_closed_and_not_reissuable() {
    let fixture = CommitFixture::new();
    let authorized = fixture.authorize();
    fixture.store.fail_next_event_append_for_test();

    let error = fixture
        .port
        .execute(authorized.clone(), 1)
        .await
        .unwrap_err();

    assert_eq!(error.code(), ErrorCode::Internal);
    assert_eq!(error.position(), ExecutionPosition::BeforeNexus);
    assert_eq!(fixture.metrics.snapshot().token_issues, 1);
    assert_eq!(fixture.metrics.snapshot().nexus_executions, 0);
    assert!(!fixture.store.event_kinds().unwrap().iter().any(|kind| {
        matches!(
            kind,
            MissionEventKind::AuthorizationConsumed | MissionEventKind::ExecutionStarted
        )
    }));
    let records = fixture.store.authorization_records().unwrap();
    assert_eq!(records[0].state, AuthorizationState::Consumed);
    assert_eq!(records[0].remaining_budget.actions, 0);

    let retry = fixture.port.execute(authorized, 2).await.unwrap_err();
    assert_eq!(retry.code(), ErrorCode::AuthorizationInvalid);
    assert_eq!(retry.position(), ExecutionPosition::BeforeNexus);
    assert_eq!(fixture.metrics.snapshot().token_issues, 1);
    assert_eq!(fixture.metrics.snapshot().nexus_executions, 0);
}

#[tokio::test]
async fn j_panicking_test_hook_is_caught_after_single_use_consumption() {
    let fixture = CommitFixture::new();
    let authorized = fixture.authorize();

    let error = fixture
        .port
        .execute_with_test_hooks(
            authorized.clone(),
            1,
            ExecutionTestHooks {
                after_authorization_consumed_under_guard: Some(Arc::new(|| {
                    panic!("deterministic test-hook panic")
                })),
            },
        )
        .await
        .unwrap_err();

    assert_eq!(error.code(), ErrorCode::Internal);
    assert_eq!(error.position(), ExecutionPosition::BeforeNexus);
    assert_eq!(fixture.metrics.snapshot().nexus_executions, 0);
    assert_eq!(
        fixture.store.authorization_records().unwrap()[0].state,
        AuthorizationState::Consumed
    );

    let retry = fixture.port.execute(authorized, 2).await.unwrap_err();
    assert_eq!(retry.code(), ErrorCode::AuthorizationInvalid);
    assert_eq!(fixture.metrics.snapshot().nexus_executions, 0);
}
