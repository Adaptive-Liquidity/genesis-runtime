use std::path::PathBuf;

use aeon_agent_runtime::{
    canonical_digest, validate_context_continuation, ActionCertificate, AgentId, AgentSpec,
    AuthorityRequest, AuthoritySet, AuthorizationId, AuthorizationState, BoundTool, Budget,
    CanonicalAction, CanonicalJson, CapabilityManifest, CertificateId, ContextTransition, Contract,
    Digest, EffectClass, EffectState, InstructionProfileRef, LeaseId, LeaseRecord, LeaseState,
    MemoryRef, MissionId, ModelRef, Objective, PermissionSet, ProtocolGate, ResourceRequest,
    RetrievalIndexRef, Role, SemanticContext, SemanticRequirements, SemanticScope, ToolId,
    ToolManifest,
};
use chrono::{Duration, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use nexus::Capability;
use rand::rngs::OsRng;
use serde_json::json;

fn digest(label: &str) -> Digest {
    canonical_digest("test-label-v1", &label).expect("digest fixture")
}

fn tool_id(value: &str) -> ToolId {
    ToolId::new(value).expect("valid tool id")
}

fn sample_context(version: u64) -> SemanticContext {
    SemanticContext {
        context_version: version,
        model_manifest_digest: digest("model"),
        resolved_system_instruction_digest: digest("instruction"),
        tool_registry_root_digest: digest("registry"),
        bound_tool_digests: vec![digest("tool-b"), digest("tool-a")],
        protocol_schema_digest: digest("protocol"),
        policy_epoch: 7,
        memory_generation: None,
        retrieval_index_generation: None,
    }
}

fn sample_spec() -> AgentSpec {
    AgentSpec {
        role: Role::new("fixture operator").expect("role"),
        objective: Objective::new("execute the registered fixture").expect("objective"),
        requested_model: ModelRef::new("model.fixture-v1").expect("model"),
        requested_tools: vec![tool_id("fixture.echo")],
        requested_authority: AuthorityRequest {
            capabilities: vec![Capability::MemoryPreview],
        },
        output_contract: Contract::new("typed-agent-message-v1").expect("contract"),
        resource_budget: ResourceRequest { max_steps: 1 },
        semantic_requirements: SemanticRequirements {
            requested_memory: None,
            requested_retrieval_index: None,
            requested_instruction_profile: Some(
                InstructionProfileRef::new("profile.fixture-v1").expect("profile"),
            ),
        },
    }
}

#[test]
fn typed_ids_json_round_trip() {
    let fixtures = json!({
        "mission": MissionId::new("mission-1").unwrap(),
        "agent": AgentId::new("agent-1").unwrap(),
        "lease": LeaseId::new("lease-1").unwrap(),
        "authorization": AuthorizationId::new("auth-1").unwrap(),
        "certificate": CertificateId::new("cert-1").unwrap(),
        "tool": ToolId::new("fixture.echo").unwrap(),
        "model": ModelRef::new("model.fixture-v1").unwrap(),
        "memory": MemoryRef::new("memory-1").unwrap(),
        "retrieval": RetrievalIndexRef::new("index-1").unwrap(),
    });
    let encoded = serde_json::to_string(&fixtures).unwrap();
    let decoded: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, fixtures);
    assert!(ToolId::new("bad id with spaces").is_err());
}

#[test]
fn agent_spec_rejects_lifecycle_credentials_and_duplicate_sources() {
    let value = serde_json::to_value(sample_spec()).unwrap();
    let object = value.as_object().unwrap();
    assert!(object.contains_key("requested_model"));
    assert!(object.contains_key("requested_tools"));
    assert!(!object.contains_key("lifecycle"));
    assert!(!object.contains_key("credentials"));

    for (field, injected) in [
        ("lifecycle", json!("active")),
        ("credentials", json!({"token": "secret"})),
        ("capability_token", json!("secret")),
        ("signing_key", json!("secret")),
    ] {
        let mut hostile = value.clone();
        hostile
            .as_object_mut()
            .unwrap()
            .insert(field.into(), injected);
        assert!(serde_json::from_value::<AgentSpec>(hostile).is_err());
    }

    for duplicate in ["requested_model", "requested_tools"] {
        let mut hostile = value.clone();
        hostile["semantic_requirements"][duplicate] = json!("duplicate");
        assert!(serde_json::from_value::<AgentSpec>(hostile).is_err());
    }
}

#[test]
fn tool_and_capability_manifest_digests_are_canonical_and_binding() {
    let first = ToolManifest::new(
        1,
        tool_id("fixture.echo"),
        b"wasm-v1",
        "_start",
        json!({"required":["value"],"type":"object"}),
        vec![
            Capability::ReadFile(PathBuf::from("/data")),
            Capability::MemoryPreview,
        ],
        EffectClass::ReadOnly,
        None,
    )
    .unwrap();
    let reordered = ToolManifest::new(
        1,
        tool_id("fixture.echo"),
        b"wasm-v1",
        "_start",
        json!({"type":"object","required":["value"]}),
        vec![
            Capability::MemoryPreview,
            Capability::ReadFile(PathBuf::from("/data")),
        ],
        EffectClass::ReadOnly,
        None,
    )
    .unwrap();
    assert_eq!(
        first.canonical_digest().unwrap(),
        reordered.canonical_digest().unwrap()
    );

    let changed = ToolManifest::new(
        1,
        tool_id("fixture.echo"),
        b"wasm-v2",
        "_start",
        json!({"required":["value"],"type":"object"}),
        vec![
            Capability::MemoryPreview,
            Capability::ReadFile(PathBuf::from("/data")),
        ],
        EffectClass::ReadOnly,
        None,
    )
    .unwrap();
    assert_ne!(
        first.canonical_digest().unwrap(),
        changed.canonical_digest().unwrap()
    );

    let bound_a = BoundTool {
        tool_id: tool_id("fixture.a"),
        tool_manifest_digest: digest("a"),
    };
    let bound_b = BoundTool {
        tool_id: tool_id("fixture.b"),
        tool_manifest_digest: digest("b"),
    };
    let manifest = |tools| CapabilityManifest {
        version: 1,
        model_manifest_digest: digest("model"),
        approved_tools: tools,
        permissions: PermissionSet {
            capabilities: vec![Capability::MemoryPreview],
        },
        runtime_config_digest: digest("runtime"),
        tool_registry_root_digest: digest("registry"),
    };
    assert_eq!(
        manifest(vec![bound_a.clone(), bound_b.clone()])
            .canonical_digest()
            .unwrap(),
        manifest(vec![bound_b, bound_a]).canonical_digest().unwrap()
    );
}

#[test]
fn semantic_context_identity_is_stable_for_metadata_and_sensitive_to_reality() {
    let original = sample_context(1);
    let version_only = sample_context(99);
    assert_eq!(
        original.canonical_digest().unwrap(),
        version_only.canonical_digest().unwrap()
    );
    assert_eq!(
        validate_context_continuation(&original.canonical_digest().unwrap(), &version_only)
            .unwrap(),
        ContextTransition::Exact
    );

    let mut reordered = original.clone();
    reordered.bound_tool_digests.reverse();
    assert_eq!(
        original.canonical_digest().unwrap(),
        reordered.canonical_digest().unwrap()
    );

    let mut mutations = Vec::new();
    let mut changed = original.clone();
    changed.model_manifest_digest = digest("changed-model");
    mutations.push(changed);
    let mut changed = original.clone();
    changed.resolved_system_instruction_digest = digest("changed-instruction");
    mutations.push(changed);
    let mut changed = original.clone();
    changed.tool_registry_root_digest = digest("changed-registry");
    mutations.push(changed);
    let mut changed = original.clone();
    changed.bound_tool_digests.push(digest("changed-tool"));
    mutations.push(changed);
    let mut changed = original.clone();
    changed.protocol_schema_digest = digest("changed-protocol");
    mutations.push(changed);
    let mut changed = original.clone();
    changed.policy_epoch += 1;
    mutations.push(changed);
    let mut changed = original.clone();
    changed.memory_generation = Some(digest("memory"));
    mutations.push(changed);
    let mut changed = original.clone();
    changed.retrieval_index_generation = Some(digest("retrieval"));
    mutations.push(changed);

    for changed in mutations {
        assert_ne!(
            original.canonical_digest().unwrap(),
            changed.canonical_digest().unwrap()
        );
        assert!(
            validate_context_continuation(&original.canonical_digest().unwrap(), &changed).is_err()
        );
    }
}

#[test]
fn lease_state_is_separate_from_signed_certificate_payload() {
    use aeon_agent_runtime::{AuthorityLeaseCertificate, SignatureBytes};

    let issued_at = Utc.with_ymd_and_hms(2026, 8, 9, 12, 0, 0).unwrap();
    let certificate = AuthorityLeaseCertificate {
        lease_id: LeaseId::new("lease-1").unwrap(),
        mission_id: MissionId::new("mission-1").unwrap(),
        agent_id: AgentId::new("agent-1").unwrap(),
        parent_agent_id: None,
        organization_version: 1,
        policy_epoch: 7,
        granted_authority: AuthoritySet {
            capabilities: vec![Capability::MemoryPreview],
        },
        delegable_authority: AuthoritySet {
            capabilities: vec![],
        },
        capability_manifest_digest: digest("manifest"),
        semantic_context_digest: digest("context"),
        issued_at,
        expires_at: issued_at + Duration::minutes(5),
        signature: SignatureBytes::new(vec![1, 2, 3]),
    };
    let payload = certificate.signing_payload().unwrap();
    let active = LeaseRecord::active(certificate.lease_id.clone());
    let revoked = LeaseRecord {
        lease_id: certificate.lease_id.clone(),
        state: LeaseState::Revoked,
        generation: 9,
        revoked_at: Some(issued_at),
        revocation_reason: Some("test revocation".into()),
    };
    assert_ne!(
        serde_json::to_value(active).unwrap(),
        serde_json::to_value(revoked).unwrap()
    );
    assert_eq!(payload, certificate.signing_payload().unwrap());
}

#[test]
fn lease_certificate_signature_detects_signed_field_mutation() {
    use aeon_agent_runtime::{AuthorityLeaseCertificate, SignatureBytes};

    let issued_at = Utc.with_ymd_and_hms(2026, 8, 9, 12, 0, 0).unwrap();
    let mut certificate = AuthorityLeaseCertificate {
        lease_id: LeaseId::new("lease-signed").unwrap(),
        mission_id: MissionId::new("mission-1").unwrap(),
        agent_id: AgentId::new("agent-1").unwrap(),
        parent_agent_id: None,
        organization_version: 1,
        policy_epoch: 7,
        granted_authority: AuthoritySet {
            capabilities: vec![Capability::MemoryPreview],
        },
        delegable_authority: AuthoritySet {
            capabilities: vec![],
        },
        capability_manifest_digest: digest("manifest"),
        semantic_context_digest: digest("context"),
        issued_at,
        expires_at: issued_at + Duration::minutes(5),
        signature: SignatureBytes::new(Vec::new()),
    };
    let signing_key = SigningKey::generate(&mut OsRng);
    certificate.signature = SignatureBytes::new(
        signing_key
            .sign(&certificate.signing_payload().unwrap())
            .to_bytes()
            .to_vec(),
    );
    assert!(certificate
        .verify_signature(&signing_key.verifying_key())
        .is_ok());

    certificate.policy_epoch += 1;
    assert!(certificate
        .verify_signature(&signing_key.verifying_key())
        .is_err());
}

#[test]
fn actions_and_certificates_are_canonical_and_state_types_are_distinct() {
    let action_a = CanonicalAction {
        mission_id: MissionId::new("mission-1").unwrap(),
        effect_kind: EffectClass::ReadOnly,
        target: "fixture.echo".into(),
        normalized_parameters: CanonicalJson::new(json!({"b":2,"a":1})),
        semantic_scope: SemanticScope::Mission,
    };
    let action_b = CanonicalAction {
        normalized_parameters: CanonicalJson::new(json!({"a":1,"b":2})),
        ..action_a.clone()
    };
    assert_eq!(
        action_a.action_ref().unwrap(),
        action_b.action_ref().unwrap()
    );

    let issued_at = Utc.with_ymd_and_hms(2026, 8, 9, 12, 0, 0).unwrap();
    let certificate = ActionCertificate::unsigned_fixture(
        CertificateId::new("cert-1").unwrap(),
        MissionId::new("mission-1").unwrap(),
        AgentId::new("agent-1").unwrap(),
        LeaseId::new("lease-1").unwrap(),
        action_a.action_ref().unwrap(),
        tool_id("fixture.echo"),
        digest("tool"),
        digest("input"),
        AuthorizationId::new("auth-1").unwrap(),
        issued_at,
    );
    let encoded = serde_json::to_value(&certificate).unwrap();
    assert!(encoded.get("consumed_uses").is_none());
    let decoded: ActionCertificate = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(decoded, certificate);
    let mut hostile = encoded;
    hostile["consumed_uses"] = json!(1);
    assert!(serde_json::from_value::<ActionCertificate>(hostile).is_err());

    assert_ne!(
        serde_json::to_value(AuthorizationState::Consumed).unwrap(),
        serde_json::to_value(EffectState::Confirmed).unwrap()
    );
    assert_eq!(
        serde_json::from_value::<EffectState>(json!("unknown_outcome")).unwrap(),
        EffectState::UnknownOutcome
    );
    let _budget = Budget { actions: 1 };
}

#[test]
fn protocol_is_closed_and_size_bounded() {
    let gate = ProtocolGate::default();
    let valid = r#"{"kind":"tool_call","tool_id":"fixture.echo","arguments":{"value":"hello"}}"#;
    assert!(gate.parse(valid).is_ok());
    assert!(gate.parse(r#"{"kind":"final","result":"done"}"#).is_ok());

    for invalid in [
        "not-json",
        r#"{"kind":"unknown"}"#,
        r#"{"kind":"tool_call","tool_id":"fixture.echo"}"#,
        r#"{"kind":"tool_call","tool_id":"fixture.echo","arguments":{},"wasm":"attack"}"#,
        r#"{"kind":"final","result":"done","token":"attack"}"#,
    ] {
        assert!(
            gate.parse(invalid).is_err(),
            "accepted invalid protocol: {invalid}"
        );
    }
    assert!(gate
        .parse(&"x".repeat(gate.max_output_bytes() + 1))
        .is_err());
}

#[test]
fn canonical_hashes_are_domain_separated() {
    let payload = json!({"same":"payload"});
    let tool = canonical_digest("aeon-tool-manifest-v1", &payload).unwrap();
    let context = canonical_digest("aeon-semantic-context-v1", &payload).unwrap();
    let action = canonical_digest("aeon-canonical-action-v1", &payload).unwrap();
    assert_ne!(tool, context);
    assert_ne!(tool, action);
    assert_ne!(context, action);
}
