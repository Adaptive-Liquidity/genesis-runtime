use std::sync::Arc;

use aeon_agent_runtime::{
    canonical_bytes, canonical_digest, ActionRef, AgentId, AgentIdentity, AgentIdentityCertificate,
    AgentLifecycle, AgentRuntimeRecord, AgentSpec, AuthorityLeaseCertificate, AuthorityRequest,
    AuthoritySet, AuthorizationId, AuthorizationRecord, AuthorizationState, Budget, CanonicalJson,
    Contract, Digest, EffectClass, ErrorCode, InMemoryKeyCustody, InMemoryMissionStore,
    InstructionProfileRef, KeyCustody, KeyId, LeaseId, LeaseRecord, LeaseRef, MemoryEntry,
    MemoryTrust, MissionEnvelope, MissionEventKind, MissionId, ModelClient, ModelRef, ModelRequest,
    Objective, ProtocolGate, RegisteredTool, ResourceRequest, Role, RuntimeError,
    ScriptedModelClient, SecurityLevel, SemanticContext, SemanticRequirements, SignatureBytes,
    ToolId, ToolRegistry,
};
use chrono::{Duration, Utc};
use nexus::Capability;
use serde_json::json;

fn digest(label: &str) -> Digest {
    canonical_digest("support-test-v1", &label).unwrap()
}

fn tool_id(value: &str) -> ToolId {
    ToolId::new(value).unwrap()
}

fn sample_spec() -> AgentSpec {
    AgentSpec {
        role: Role::new("operator").unwrap(),
        objective: Objective::new("exercise support contracts").unwrap(),
        requested_model: ModelRef::new("model.fixture-v1").unwrap(),
        requested_tools: vec![tool_id("fixture.echo")],
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
    }
}

fn sample_context() -> SemanticContext {
    SemanticContext {
        context_version: 1,
        model_manifest_digest: digest("model"),
        resolved_system_instruction_digest: digest("instruction"),
        tool_registry_root_digest: digest("registry"),
        bound_tool_digests: vec![digest("tool")],
        protocol_schema_digest: digest("protocol"),
        policy_epoch: 7,
        memory_generation: None,
        retrieval_index_generation: None,
    }
}

fn sample_mission() -> MissionEnvelope {
    MissionEnvelope {
        mission_id: MissionId::new("mission-1").unwrap(),
        allowed_tools: vec![tool_id("fixture.echo")],
        allowed_capabilities: vec![Capability::MemoryPreview],
        policy_epoch: 7,
        organization_version: 1,
        active: true,
        expires_at: Utc::now() + Duration::minutes(5),
        max_actions: 1,
    }
}

fn fixture_tool() -> RegisteredTool {
    RegisteredTool::new(
        tool_id("fixture.echo"),
        wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "_start")))"#)
            .unwrap(),
        "_start",
        json!({
            "type":"object",
            "required":["value"],
            "properties":{"value":{"type":"string"}},
            "additionalProperties":false
        }),
        vec![Capability::MemoryPreview],
        EffectClass::ReadOnly,
        None,
    )
    .unwrap()
}

#[test]
fn error_codes_have_stable_display_and_messages() {
    let codes = [
        ErrorCode::InvalidIdentifier,
        ErrorCode::InvalidInput,
        ErrorCode::CanonicalSerialization,
        ErrorCode::MalformedProtocol,
        ErrorCode::OutputTooLarge,
        ErrorCode::UnknownTool,
        ErrorCode::DuplicateTool,
        ErrorCode::ToolOutsideMission,
        ErrorCode::CapabilityOutsideAuthority,
        ErrorCode::CapabilityAllForbidden,
        ErrorCode::ToolManifestMismatch,
        ErrorCode::SemanticContextChanged,
        ErrorCode::ContextResolutionFailed,
        ErrorCode::MissionInactive,
        ErrorCode::BudgetExhausted,
        ErrorCode::AgentInactive,
        ErrorCode::LeaseInactive,
        ErrorCode::IdentityInvalid,
        ErrorCode::DelegationInvalid,
        ErrorCode::LeaseGenerationMismatch,
        ErrorCode::CapabilityManifestMismatch,
        ErrorCode::AuthorizationInvalid,
        ErrorCode::ExecutionFailed,
        ErrorCode::ModelFailed,
        ErrorCode::EventIncomplete,
        ErrorCode::Internal,
    ];
    for code in codes {
        let error = RuntimeError::new(code, "detail");
        assert_eq!(error.code(), code);
        assert_eq!(error.message(), "detail");
        assert!(error.to_string().ends_with(": detail"));
        let as_error: &dyn std::error::Error = &error;
        assert!(as_error.source().is_none());
    }
}

#[test]
fn digest_hex_bytes_and_canonical_json_edges_are_validated() {
    let bytes = [0xabu8; 32];
    let value = Digest::from_slice(&bytes).unwrap();
    assert_eq!(value.as_bytes(), &bytes);
    assert_eq!(Digest::from_hex(&value.to_hex()).unwrap(), value);
    assert_eq!(format!("{value}"), value.to_hex());
    assert!(format!("{value:?}").starts_with("Digest("));
    assert!(Digest::from_slice(&bytes[..31]).is_err());
    assert!(Digest::from_hex("ab").is_err());
    assert!(Digest::from_hex(&"G".repeat(64)).is_err());
    assert!(serde_json::from_value::<Digest>(json!("not-a-digest")).is_err());

    let canonical = CanonicalJson::new(json!({"z":[{"b":2,"a":1}],"a":true}));
    assert_eq!(canonical.as_value()["z"][0], json!({"a":1,"b":2}));
    let encoded = serde_json::to_string(&canonical).unwrap();
    let decoded: CanonicalJson = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.into_value(), canonical.into_value());
    assert!(canonical_digest("", &json!({})).is_err());
    let framed = canonical_bytes("domain-v1", &json!({"b":2,"a":1})).unwrap();
    assert!(framed
        .windows("domain-v1".len())
        .any(|part| part == b"domain-v1"));
}

#[test]
fn identifier_helpers_preserve_validation() {
    let id = ToolId::new("fixture.echo/v1@local").unwrap();
    assert_eq!(id.as_str(), "fixture.echo/v1@local");
    assert_eq!(id.as_ref(), "fixture.echo/v1@local");
    assert_eq!(id.to_string(), "fixture.echo/v1@local");
    assert_eq!(ToolId::try_from(id.to_string()).unwrap(), id);
    assert_eq!(id.clone().into_inner(), "fixture.echo/v1@local");
    assert!(ToolId::new("").is_err());
    assert!(ToolId::new("-leading").is_err());
    assert!(ToolId::new("bad space").is_err());
    assert!(ToolId::new("x".repeat(129)).is_err());
    assert!(serde_json::from_value::<ToolId>(json!("bad space")).is_err());
}

#[test]
fn identity_certificates_bind_agent_key_and_issuer_without_exposing_private_keys() {
    let issuer = InMemoryKeyCustody::generate(KeyId::new("key-issuer").unwrap()).unwrap();
    let subject = InMemoryKeyCustody::generate(KeyId::new("key-subject").unwrap()).unwrap();
    let mut certificate = AgentIdentityCertificate::unsigned(
        AgentId::new("agent-subject").unwrap(),
        subject.key_id(),
        subject.verifying_key(),
        Some(AgentId::new("agent-issuer").unwrap()),
        issuer.key_id(),
        Utc::now(),
    );
    certificate.signature = issuer
        .sign(&certificate.signing_payload().unwrap())
        .unwrap();

    certificate
        .verify_signature(&issuer.verifying_key())
        .unwrap();
    assert_eq!(
        certificate.verifying_key().unwrap(),
        subject.verifying_key()
    );
    assert!(!certificate.canonical_digest().unwrap().to_hex().is_empty());

    let debug = format!("{issuer:?}").to_ascii_lowercase();
    assert!(debug.contains("key-issuer"));
    assert!(!debug.contains("signing_key"));
    assert!(!debug.contains("secret"));

    certificate.agent_id = AgentId::new("agent-substituted").unwrap();
    assert_eq!(
        certificate
            .verify_signature(&issuer.verifying_key())
            .unwrap_err()
            .code(),
        ErrorCode::IdentityInvalid
    );
}

#[test]
fn mission_predicates_are_default_deny() {
    let mission = sample_mission();
    assert!(mission.is_usable_at(Utc::now()));
    assert!(mission.allows_tool(&tool_id("fixture.echo")));
    assert!(!mission.allows_tool(&tool_id("fixture.missing")));
    assert!(mission.allows_capability(&Capability::MemoryPreview));
    assert!(!mission.allows_capability(&Capability::ReadFile("/data".into())));
    assert!(!mission.contains_capability_all());

    let mut unusable = mission;
    unusable.active = false;
    assert!(!unusable.is_usable_at(Utc::now()));
    unusable.active = true;
    unusable.max_actions = 0;
    assert!(!unusable.is_usable_at(Utc::now()));
    unusable.allowed_capabilities.push(Capability::All);
    assert!(unusable.contains_capability_all());
}

#[test]
fn authority_sets_use_nexus_attenuation_semantics() {
    let parent = AuthoritySet::new(vec![Capability::ReadFile("/data".into())]).unwrap();
    let child = AuthoritySet::new(vec![Capability::ReadFile("/data/reports".into())]).unwrap();
    assert!(child.is_subset_of(&parent));
    assert!(parent.covers(&Capability::ReadFile("/data/reports/a.json".into())));
    assert!(!parent.is_subset_of(&child));
    assert!(AuthoritySet::new(vec![Capability::All]).is_err());
}

#[test]
fn memory_entries_preserve_mandatory_trust_and_provenance_fields() {
    let created_at = Utc::now();
    let entry = MemoryEntry {
        content: b"advisory memory".to_vec(),
        checksum: digest("memory-content"),
        confidentiality: SecurityLevel::Confidential,
        integrity: SecurityLevel::Restricted,
        source_agent: AgentId::new("agent-source").unwrap(),
        source_identity_digest: digest("source-identity"),
        created_at,
        trust_class: MemoryTrust::SourceVerified,
        ttl_seconds: 60,
        expires_at: created_at + Duration::seconds(60),
        semantic_context_digest: digest("context"),
    };
    let encoded = serde_json::to_value(&entry).unwrap();
    assert_eq!(encoded["trust_class"], json!("source_verified"));
    assert_eq!(encoded["ttl_seconds"], json!(60));
    assert_eq!(
        serde_json::from_value::<MemoryEntry>(encoded).unwrap(),
        entry
    );
}

#[tokio::test]
async fn scripted_model_records_only_bounded_model_facing_data_and_exhausts() {
    let model = Arc::new(ScriptedModelClient::new([
        r#"{"kind":"final","result":"done"}"#,
    ]));
    assert_eq!(model.remaining_responses(), 1);
    let request = ModelRequest {
        agent_id: AgentId::new("agent-1").unwrap(),
        spec: sample_spec(),
        semantic_context: sample_context(),
        resolved_system_instruction: "trusted instruction".into(),
    };
    let response = model.generate(request.clone()).await.unwrap();
    assert!(response.raw_output.contains("final"));
    assert_eq!(model.remaining_responses(), 0);
    assert_eq!(model.trace().len(), 1);
    assert!(model.generate(request).await.is_err());
    assert_ne!(
        model
            .manifest_digest(&ModelRef::new("model.fixture-v1").unwrap())
            .unwrap(),
        digest("unrelated")
    );
}

#[test]
fn protocol_gate_configuration_and_output_limits_fail_closed() {
    assert!(ProtocolGate::new(0).is_err());
    let gate = ProtocolGate::new(4).unwrap();
    let error = gate.parse("12345").unwrap_err();
    assert_eq!(error.code(), ErrorCode::OutputTooLarge);
}

#[test]
fn tool_registry_rejects_bad_manifests_and_inputs() {
    let base = fixture_tool();
    assert!(RegisteredTool::new(
        tool_id("fixture.empty"),
        Vec::new(),
        "_start",
        json!({}),
        vec![],
        EffectClass::ReadOnly,
        None,
    )
    .is_err());
    for bad_schema in [
        json!("not-object"),
        json!({"required":"value"}),
        json!({"required":[1]}),
        json!({"properties":[]}),
        json!({"type":"string","pattern":".*"}),
        json!({"type":"mystery"}),
        json!({"additionalProperties":{}}),
        json!({"properties":{"value":{"type":"string","minLength":1}}}),
    ] {
        assert!(RegisteredTool::new(
            tool_id("fixture.bad"),
            vec![1],
            "_start",
            bad_schema,
            vec![],
            EffectClass::ReadOnly,
            None,
        )
        .is_err());
    }
    assert!(RegisteredTool::new(
        tool_id("fixture.bad-output"),
        vec![1],
        "_start",
        json!({}),
        vec![],
        EffectClass::ReadOnly,
        Some(json!("bad-output-schema")),
    )
    .is_err());

    assert!(base.validate_input(&json!("not-object")).is_err());
    assert!(base.validate_input(&json!({})).is_err());
    assert!(base.validate_input(&json!({"value":1})).is_err());
    assert!(base
        .validate_input(&json!({"value":"ok","extra":true}))
        .is_err());
    assert!(base.validate_input(&json!({"value":"ok"})).is_ok());
    assert!(base.output_schema().is_none());
    assert_eq!(base.input_schema()["type"], "object");

    assert!(ToolRegistry::from_tools(vec![base.clone(), base.clone()]).is_err());
    let registry = ToolRegistry::from_tools(vec![base]).unwrap();
    assert!(registry.resolve(&tool_id("fixture.missing")).is_err());
    assert!(registry.replace(fixture_tool()).is_ok());
    assert!(registry.root_digest().is_ok());
}

fn append_foundation(store: &InMemoryMissionStore) {
    for kind in [
        MissionEventKind::MissionCreated,
        MissionEventKind::ContextResolved,
        MissionEventKind::LeaseIssued,
        MissionEventKind::AgentActivated,
    ] {
        store.append(kind);
    }
}

fn append_attempt(
    store: &InMemoryMissionStore,
    attempt_id: u64,
    events: impl IntoIterator<Item = MissionEventKind>,
) {
    for event in events {
        store.append_for_attempt(attempt_id, event);
    }
}

fn successful_attempt() -> Vec<MissionEventKind> {
    vec![
        MissionEventKind::ProtocolAccepted,
        MissionEventKind::PlanAccepted,
        MissionEventKind::ActionAuthorized,
        MissionEventKind::AuthorizationIssued,
        MissionEventKind::AuthorizationConsumed,
        MissionEventKind::ExecutionStarted,
        MissionEventKind::ExecutionCompleted,
    ]
}

fn protocol_rejected_attempt() -> Vec<MissionEventKind> {
    vec![MissionEventKind::ProtocolRejected(
        ErrorCode::MalformedProtocol,
    )]
}

fn action_rejected_attempt() -> Vec<MissionEventKind> {
    vec![
        MissionEventKind::ProtocolAccepted,
        MissionEventKind::PlanAccepted,
        MissionEventKind::ActionRejected(ErrorCode::UnknownTool),
    ]
}

fn pre_nexus_rejected_attempt() -> Vec<MissionEventKind> {
    vec![
        MissionEventKind::ProtocolAccepted,
        MissionEventKind::PlanAccepted,
        MissionEventKind::ActionAuthorized,
        MissionEventKind::AuthorizationIssued,
        MissionEventKind::ExecutionRejectedBeforeNexus(ErrorCode::ToolManifestMismatch),
    ]
}

#[test]
fn mission_store_accepts_complete_histories_across_attempt_boundaries() {
    let histories = [
        (successful_attempt(), protocol_rejected_attempt()),
        (protocol_rejected_attempt(), successful_attempt()),
        (successful_attempt(), action_rejected_attempt()),
        (action_rejected_attempt(), successful_attempt()),
        (pre_nexus_rejected_attempt(), successful_attempt()),
        (successful_attempt(), successful_attempt()),
    ];

    for (first, second) in histories {
        let store = InMemoryMissionStore::new(sample_mission());
        append_foundation(&store);
        let first_attempt = store.begin_attempt();
        append_attempt(&store, first_attempt, first);
        let second_attempt = store.begin_attempt();
        append_attempt(&store, second_attempt, second);

        store.verify_event_completeness().unwrap();
    }

    let interleaved = InMemoryMissionStore::new(sample_mission());
    append_foundation(&interleaved);
    let final_attempt = interleaved.begin_attempt();
    let rejected_attempt = interleaved.begin_attempt();
    interleaved.append_for_attempt(final_attempt, MissionEventKind::ProtocolAccepted);
    interleaved.append_for_attempt(
        rejected_attempt,
        MissionEventKind::ProtocolRejected(ErrorCode::MalformedProtocol),
    );
    interleaved.append_for_attempt(final_attempt, MissionEventKind::FinalProduced);
    interleaved.verify_event_completeness().unwrap();
}

#[test]
fn mission_store_detects_incomplete_rejection_and_execution_histories() {
    let empty = InMemoryMissionStore::new(sample_mission());
    assert!(empty.verify_event_completeness().is_err());
    assert_eq!(empty.mission().mission_id.as_str(), "mission-1");

    let protocol_rejected = InMemoryMissionStore::new(sample_mission());
    append_foundation(&protocol_rejected);
    let attempt = protocol_rejected.begin_attempt();
    append_attempt(
        &protocol_rejected,
        attempt,
        [
            MissionEventKind::ProtocolRejected(ErrorCode::MalformedProtocol),
            MissionEventKind::ExecutionStarted,
        ],
    );
    assert!(protocol_rejected.verify_event_completeness().is_err());

    let action_rejected = InMemoryMissionStore::new(sample_mission());
    append_foundation(&action_rejected);
    let attempt = action_rejected.begin_attempt();
    append_attempt(
        &action_rejected,
        attempt,
        [
            MissionEventKind::ProtocolAccepted,
            MissionEventKind::PlanAccepted,
            MissionEventKind::ActionRejected(ErrorCode::UnknownTool),
            MissionEventKind::AuthorizationIssued,
        ],
    );
    assert!(action_rejected.verify_event_completeness().is_err());

    let consumed_without_issue = InMemoryMissionStore::new(sample_mission());
    append_foundation(&consumed_without_issue);
    let attempt = consumed_without_issue.begin_attempt();
    append_attempt(
        &consumed_without_issue,
        attempt,
        [
            MissionEventKind::ProtocolAccepted,
            MissionEventKind::PlanAccepted,
            MissionEventKind::ActionAuthorized,
            MissionEventKind::AuthorizationConsumed,
        ],
    );
    assert!(consumed_without_issue.verify_event_completeness().is_err());

    let completed_without_start = InMemoryMissionStore::new(sample_mission());
    append_foundation(&completed_without_start);
    let attempt = completed_without_start.begin_attempt();
    append_attempt(
        &completed_without_start,
        attempt,
        [
            MissionEventKind::ProtocolAccepted,
            MissionEventKind::PlanAccepted,
            MissionEventKind::ActionAuthorized,
            MissionEventKind::AuthorizationIssued,
            MissionEventKind::AuthorizationConsumed,
            MissionEventKind::ExecutionCompleted,
        ],
    );
    assert!(completed_without_start.verify_event_completeness().is_err());

    let before_nexus = InMemoryMissionStore::new(sample_mission());
    append_foundation(&before_nexus);
    let attempt = before_nexus.begin_attempt();
    append_attempt(
        &before_nexus,
        attempt,
        [
            MissionEventKind::ProtocolAccepted,
            MissionEventKind::PlanAccepted,
            MissionEventKind::ActionAuthorized,
            MissionEventKind::AuthorizationIssued,
            MissionEventKind::ExecutionRejectedBeforeNexus(ErrorCode::ToolManifestMismatch),
            MissionEventKind::ExecutionCompleted,
        ],
    );
    assert!(before_nexus.verify_event_completeness().is_err());

    let started_without_terminal = InMemoryMissionStore::new(sample_mission());
    append_foundation(&started_without_terminal);
    let attempt = started_without_terminal.begin_attempt();
    append_attempt(
        &started_without_terminal,
        attempt,
        [
            MissionEventKind::ProtocolAccepted,
            MissionEventKind::PlanAccepted,
            MissionEventKind::ActionAuthorized,
            MissionEventKind::AuthorizationIssued,
            MissionEventKind::AuthorizationConsumed,
            MissionEventKind::ExecutionStarted,
        ],
    );
    assert!(started_without_terminal
        .verify_event_completeness()
        .is_err());

    let order_corrupted = InMemoryMissionStore::new(sample_mission());
    append_foundation(&order_corrupted);
    let attempt = order_corrupted.begin_attempt();
    append_attempt(
        &order_corrupted,
        attempt,
        [
            MissionEventKind::ProtocolAccepted,
            MissionEventKind::PlanAccepted,
            MissionEventKind::ActionAuthorized,
            MissionEventKind::AuthorizationIssued,
            MissionEventKind::ExecutionStarted,
            MissionEventKind::AuthorizationConsumed,
            MissionEventKind::ExecutionCompleted,
        ],
    );
    assert!(order_corrupted.verify_event_completeness().is_err());
}

#[test]
fn mission_store_keeps_agent_lease_and_authorization_records_separate() {
    let store = InMemoryMissionStore::new(sample_mission());
    append_foundation(&store);
    let context = sample_context();
    let context_digest = context.canonical_digest().unwrap();
    let agent_id = AgentId::new("agent-1").unwrap();
    let lease_id = LeaseId::new("lease-1").unwrap();
    let agent = AgentRuntimeRecord {
        spec_digest: digest("spec"),
        identity: AgentIdentity {
            agent_id: agent_id.clone(),
            identity_digest: digest("agent"),
        },
        lease_id: lease_id.clone(),
        lifecycle: AgentLifecycle::Active,
        current_step: 0,
        semantic_context: context,
        semantic_context_digest: context_digest,
    };
    store.set_agent_record(agent.clone());
    assert_eq!(store.agent_record(), Some(agent));

    let now = Utc::now();
    let certificate = AuthorityLeaseCertificate {
        lease_id: lease_id.clone(),
        mission_id: MissionId::new("mission-1").unwrap(),
        agent_id,
        parent_agent_id: None,
        agent_identity_digest: digest("agent-identity"),
        issuer_identity_digest: digest("issuer-identity"),
        issuer_key_id: KeyId::new("key-issuer").unwrap(),
        parent_lease: None,
        renewed_from: None,
        organization_version: 1,
        policy_epoch: 7,
        granted_authority: AuthoritySet {
            capabilities: vec![Capability::MemoryPreview],
        },
        delegable_authority: AuthoritySet {
            capabilities: vec![],
        },
        capability_manifest_digest: digest("manifest"),
        semantic_context_digest: context_digest,
        issued_at: now,
        expires_at: now + Duration::minutes(5),
        signature: SignatureBytes::new(vec![]),
    };
    let lease_record = LeaseRecord::active(lease_id.clone());
    store.set_lease(certificate.clone(), lease_record.clone());
    assert_eq!(store.lease(), Some((certificate, lease_record)));

    let authorization = AuthorizationRecord {
        record_id: AuthorizationId::new("auth-1").unwrap(),
        action_ref: ActionRef::new(digest("action")),
        authority_chain: vec![LeaseRef {
            lease_id,
            certificate_digest: digest("lease-cert"),
        }],
        total_budget: Budget { actions: 1 },
        remaining_budget: Budget { actions: 1 },
        state: AuthorizationState::Issued,
        stable_idempotency_key: "idem-1".into(),
        effect_class: EffectClass::ReadOnly,
        generation: 0,
    };
    store.insert_authorization(authorization.clone()).unwrap();
    assert_eq!(store.authorization_records(), vec![authorization.clone()]);
    assert_eq!(store.authorization_count(), 1);
    assert!(store.insert_authorization(authorization.clone()).is_err());
    let encoded = serde_json::to_value(&authorization).unwrap();
    assert!(encoded.get("budget").is_none());
    assert_eq!(encoded["total_budget"]["actions"], json!(1));
    assert_eq!(encoded["remaining_budget"]["actions"], json!(1));
    let consumed = store
        .consume_authorization(&authorization.record_id, authorization.generation)
        .unwrap();
    assert_eq!(consumed.state, AuthorizationState::Consumed);
    assert_eq!(consumed.remaining_budget.actions, 0);
    assert_eq!(consumed.generation, 1);
    assert!(store
        .consume_authorization(&authorization.record_id, authorization.generation)
        .is_err());
    assert_eq!(store.events().len(), 4);
    assert!(store.verify_event_completeness().is_ok());
}
