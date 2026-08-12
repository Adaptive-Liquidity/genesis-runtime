use std::sync::Arc;

use aeon_agent_runtime::{
    canonical_digest, AuthorityEvent, AuthorityEventKind, AuthorityKernel, AuthoritySet, BoundTool,
    CapabilityManifest, DelegationRequest, Digest, ErrorCode, InMemoryKeyCustody, KeyCustody,
    KeyId, LeaseId, LeaseSnapshot, LeaseState, MissionEnvelope, MissionId, PermissionSet,
    RenewalRequest, RootLeaseRequest, ToolId, MAX_AUTHORITY_CHAIN_DEPTH,
};
use chrono::{Duration, TimeZone, Utc};
use nexus::Capability;

fn digest(label: &str) -> Digest {
    canonical_digest("aeon-r2-test-v1", &label).unwrap()
}

fn tool_id(value: &str) -> ToolId {
    ToolId::new(value).unwrap()
}

fn authority_set(capabilities: Vec<Capability>) -> AuthoritySet {
    AuthoritySet::new(capabilities).unwrap()
}

fn manifest(capabilities: Vec<Capability>, tools: Vec<(&str, &str)>) -> CapabilityManifest {
    CapabilityManifest {
        version: 1,
        model_manifest_digest: digest("model"),
        approved_tools: tools
            .into_iter()
            .map(|(id, implementation)| BoundTool {
                tool_id: tool_id(id),
                tool_manifest_digest: digest(implementation),
            })
            .collect(),
        permissions: PermissionSet { capabilities },
        runtime_config_digest: digest("runtime"),
        tool_registry_root_digest: digest("registry"),
    }
}

fn mission(now: chrono::DateTime<Utc>) -> MissionEnvelope {
    MissionEnvelope {
        mission_id: MissionId::new("mission-r2").unwrap(),
        allowed_tools: vec![tool_id("fixture.echo"), tool_id("fixture.read")],
        allowed_capabilities: vec![
            Capability::ReadFile("/data".into()),
            Capability::MemoryPreview,
        ],
        policy_epoch: 9,
        organization_version: 3,
        active: true,
        expires_at: now + Duration::hours(1),
        max_actions: 8,
    }
}

struct Fixture {
    now: chrono::DateTime<Utc>,
    kernel: AuthorityKernel,
    root_key: Arc<InMemoryKeyCustody>,
    root_manifest: CapabilityManifest,
}

fn fixture() -> Fixture {
    let now = Utc.with_ymd_and_hms(2026, 8, 10, 12, 0, 0).unwrap();
    let root_key =
        Arc::new(InMemoryKeyCustody::generate(KeyId::new("key-root-1").unwrap()).unwrap());
    let capabilities = vec![
        Capability::ReadFile("/data".into()),
        Capability::MemoryPreview,
    ];
    let root_manifest = manifest(
        capabilities.clone(),
        vec![("fixture.echo", "echo-v1"), ("fixture.read", "read-v1")],
    );
    let kernel = AuthorityKernel::bootstrap(
        RootLeaseRequest {
            mission: mission(now),
            agent_id: aeon_agent_runtime::AgentId::new("agent-root").unwrap(),
            granted_authority: authority_set(capabilities.clone()),
            delegable_authority: authority_set(capabilities),
            capability_manifest: root_manifest.clone(),
            semantic_context_digest: digest("root-context"),
            expires_at: now + Duration::minutes(45),
        },
        root_key.clone(),
        now,
    )
    .unwrap();
    Fixture {
        now,
        kernel,
        root_key,
        root_manifest,
    }
}

fn delegate_child(
    fixture: &Fixture,
    parent_lease_id: aeon_agent_runtime::LeaseId,
    parent_generation: u64,
    child_agent: &str,
    child_key: Arc<InMemoryKeyCustody>,
    capability: Capability,
    tool: (&str, &str),
) -> aeon_agent_runtime::LeaseId {
    fixture
        .kernel
        .delegate(
            DelegationRequest {
                parent_lease_id,
                expected_parent_generation: parent_generation,
                child_agent_id: aeon_agent_runtime::AgentId::new(child_agent).unwrap(),
                granted_authority: authority_set(vec![capability.clone()]),
                delegable_authority: authority_set(vec![capability.clone()]),
                capability_manifest: manifest(vec![capability], vec![tool]),
                semantic_context_digest: digest(&format!("{child_agent}-context")),
                expires_at: fixture.now + Duration::minutes(30),
            },
            child_key,
            fixture.now,
        )
        .unwrap()
}

#[test]
fn cryptographic_agent_identity_is_issuer_bound_and_key_custody_is_redacted() {
    let fixture = fixture();
    let root_lease_id = fixture.kernel.root_lease_id().unwrap();
    let root_identity = fixture
        .kernel
        .identity_certificate(&aeon_agent_runtime::AgentId::new("agent-root").unwrap())
        .unwrap();
    root_identity.verify_self_signed().unwrap();
    assert_eq!(root_identity.key_id, fixture.root_key.key_id());
    assert_eq!(
        fixture
            .kernel
            .lease_snapshot(&root_lease_id)
            .unwrap()
            .certificate
            .agent_identity_digest,
        root_identity.canonical_digest().unwrap()
    );

    let debug = format!("{:?}", fixture.root_key).to_ascii_lowercase();
    assert!(debug.contains("key-root-1"));
    assert!(!debug.contains("signing_key"));
    assert!(!debug.contains("secret"));
}

#[test]
fn delegated_chain_is_signed_and_transitively_attenuated() {
    let fixture = fixture();
    let root = fixture.kernel.root_lease_id().unwrap();
    let child_key =
        Arc::new(InMemoryKeyCustody::generate(KeyId::new("key-child-1").unwrap()).unwrap());
    let child = delegate_child(
        &fixture,
        root,
        0,
        "agent-child",
        child_key,
        Capability::ReadFile("/data/reports".into()),
        ("fixture.read", "read-v1"),
    );
    let grandchild = delegate_child(
        &fixture,
        child,
        0,
        "agent-grandchild",
        Arc::new(InMemoryKeyCustody::generate(KeyId::new("key-grandchild-1").unwrap()).unwrap()),
        Capability::ReadFile("/data/reports/final".into()),
        ("fixture.read", "read-v1"),
    );
    let leaf = fixture.kernel.lease_snapshot(&grandchild).unwrap();
    let validated = fixture
        .kernel
        .validate_active_chain(&grandchild, Some(0), &leaf.manifest, fixture.now)
        .unwrap();
    assert_eq!(validated.chain.len(), 3);
    assert_eq!(validated.leaf_lease_id, grandchild);
}

#[test]
fn delegation_rejects_capability_tool_expiry_and_all_expansion() {
    let fixture = fixture();
    let root = fixture.kernel.root_lease_id().unwrap();
    let child_key = || {
        Arc::new(
            InMemoryKeyCustody::generate(
                KeyId::new(format!("key-child-{}", uuid::Uuid::new_v4())).unwrap(),
            )
            .unwrap(),
        )
    };
    let request = |capability: Capability, tool: (&str, &str), expires_at| DelegationRequest {
        parent_lease_id: root.clone(),
        expected_parent_generation: 0,
        child_agent_id: aeon_agent_runtime::AgentId::new(format!(
            "agent-child-{}",
            uuid::Uuid::new_v4()
        ))
        .unwrap(),
        granted_authority: authority_set(vec![capability.clone()]),
        delegable_authority: authority_set(vec![capability.clone()]),
        capability_manifest: manifest(vec![capability], vec![tool]),
        semantic_context_digest: digest("child-context"),
        expires_at,
    };

    for invalid in [
        request(
            Capability::WriteFile("/data/report".into()),
            ("fixture.read", "read-v1"),
            fixture.now + Duration::minutes(20),
        ),
        request(
            Capability::ReadFile("/data/report".into()),
            ("fixture.unbound", "other-v1"),
            fixture.now + Duration::minutes(20),
        ),
        request(
            Capability::ReadFile("/data/report".into()),
            ("fixture.read", "read-v1"),
            fixture.now + Duration::minutes(50),
        ),
    ] {
        assert!(fixture
            .kernel
            .delegate(invalid, child_key(), fixture.now)
            .is_err());
    }

    let error = AuthoritySet::new(vec![Capability::All]).unwrap_err();
    assert_eq!(error.code(), ErrorCode::CapabilityAllForbidden);
}

#[test]
fn pause_blocks_the_entire_chain_and_resume_restores_it() {
    let fixture = fixture();
    let root = fixture.kernel.root_lease_id().unwrap();
    let child = delegate_child(
        &fixture,
        root.clone(),
        0,
        "agent-child",
        Arc::new(InMemoryKeyCustody::generate(KeyId::new("key-child-1").unwrap()).unwrap()),
        Capability::ReadFile("/data/reports".into()),
        ("fixture.read", "read-v1"),
    );
    let child_manifest = fixture.kernel.lease_snapshot(&child).unwrap().manifest;

    let paused = fixture.kernel.pause(&root, 0, fixture.now).unwrap();
    assert_eq!(paused.state, LeaseState::Paused);
    assert!(fixture
        .kernel
        .validate_active_chain(&child, Some(0), &child_manifest, fixture.now)
        .is_err());
    let resumed = fixture.kernel.resume(&root, 1, fixture.now).unwrap();
    assert_eq!(resumed.state, LeaseState::Active);
    fixture
        .kernel
        .validate_active_chain(&child, Some(0), &child_manifest, fixture.now)
        .unwrap();
}

#[test]
fn revocation_is_generation_checked_and_cascades_to_descendants() {
    let fixture = fixture();
    let root = fixture.kernel.root_lease_id().unwrap();
    let child = delegate_child(
        &fixture,
        root.clone(),
        0,
        "agent-child",
        Arc::new(InMemoryKeyCustody::generate(KeyId::new("key-child-1").unwrap()).unwrap()),
        Capability::ReadFile("/data/reports".into()),
        ("fixture.read", "read-v1"),
    );

    let error = fixture
        .kernel
        .revoke(&root, 9, "stale writer", fixture.now)
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::LeaseGenerationMismatch);
    fixture
        .kernel
        .revoke(&root, 0, "principal revoked", fixture.now)
        .unwrap();
    assert_eq!(
        fixture.kernel.lease_snapshot(&root).unwrap().record.state,
        LeaseState::Revoked
    );
    assert_eq!(
        fixture.kernel.lease_snapshot(&child).unwrap().record.state,
        LeaseState::Revoked
    );
}

#[test]
fn expiration_fails_closed_and_is_reflected_in_mutable_records() {
    let fixture = fixture();
    let root = fixture.kernel.root_lease_id().unwrap();
    let expired = fixture
        .kernel
        .refresh_expirations(fixture.now + Duration::minutes(46))
        .unwrap();
    assert!(expired.contains(&root));
    assert_eq!(
        fixture.kernel.lease_snapshot(&root).unwrap().record.state,
        LeaseState::Expired
    );
    assert!(fixture
        .kernel
        .validate_active_chain(
            &root,
            None,
            &fixture.root_manifest,
            fixture.now + Duration::minutes(46)
        )
        .is_err());
}

#[test]
fn renewal_creates_a_new_certificate_retires_old_and_invalidates_children() {
    let fixture = fixture();
    let root = fixture.kernel.root_lease_id().unwrap();
    let original = fixture.kernel.lease_snapshot(&root).unwrap();
    let child = delegate_child(
        &fixture,
        root.clone(),
        0,
        "agent-child",
        Arc::new(InMemoryKeyCustody::generate(KeyId::new("key-child-1").unwrap()).unwrap()),
        Capability::ReadFile("/data/reports".into()),
        ("fixture.read", "read-v1"),
    );

    let renewed = fixture
        .kernel
        .renew(
            RenewalRequest {
                lease_id: root.clone(),
                expected_generation: 0,
                granted_authority: original.certificate.granted_authority.clone(),
                delegable_authority: original.certificate.delegable_authority.clone(),
                capability_manifest: fixture.root_manifest.clone(),
                semantic_context_digest: original.certificate.semantic_context_digest,
                expires_at: fixture.now + Duration::minutes(50),
            },
            fixture.now + Duration::minutes(5),
        )
        .unwrap();
    assert_ne!(renewed, root);
    assert_eq!(
        fixture.kernel.lease_snapshot(&root).unwrap().certificate,
        original.certificate
    );
    assert_eq!(
        fixture.kernel.lease_snapshot(&root).unwrap().record.state,
        LeaseState::Retired
    );
    assert_eq!(
        fixture.kernel.lease_snapshot(&child).unwrap().record.state,
        LeaseState::Revoked
    );
    fixture
        .kernel
        .validate_active_chain(
            &renewed,
            Some(0),
            &fixture.root_manifest,
            fixture.now + Duration::minutes(5),
        )
        .unwrap();
}

#[test]
fn renewal_cannot_resurrect_revoked_authority() {
    let fixture = fixture();
    let root = fixture.kernel.root_lease_id().unwrap();
    let original = fixture.kernel.lease_snapshot(&root).unwrap();
    fixture
        .kernel
        .revoke(&root, 0, "principal revoked", fixture.now)
        .unwrap();
    let error = fixture
        .kernel
        .renew(
            RenewalRequest {
                lease_id: root,
                expected_generation: 1,
                granted_authority: original.certificate.granted_authority.clone(),
                delegable_authority: original.certificate.delegable_authority,
                capability_manifest: fixture.root_manifest,
                semantic_context_digest: original.certificate.semantic_context_digest,
                expires_at: fixture.now + Duration::minutes(50),
            },
            fixture.now + Duration::minutes(5),
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::LeaseInactive);
}

#[test]
fn renewal_rejects_semantic_context_drift_without_mutating_authority_state() {
    let fixture = fixture();
    let root = fixture.kernel.root_lease_id().unwrap();
    let before = fixture.kernel.lease_snapshot(&root).unwrap();
    let events_before = fixture.kernel.events().unwrap();

    let error = fixture
        .kernel
        .renew(
            RenewalRequest {
                lease_id: root.clone(),
                expected_generation: before.record.generation,
                granted_authority: before.certificate.granted_authority.clone(),
                delegable_authority: before.certificate.delegable_authority.clone(),
                capability_manifest: fixture.root_manifest.clone(),
                semantic_context_digest: digest("semantic-drift"),
                expires_at: fixture.now + Duration::minutes(50),
            },
            fixture.now + Duration::minutes(5),
        )
        .unwrap_err();

    assert_eq!(error.code(), ErrorCode::SemanticContextChanged);
    assert_eq!(fixture.kernel.root_lease_id().unwrap(), root);
    assert_eq!(fixture.kernel.lease_snapshot(&root).unwrap(), before);
    assert_eq!(fixture.kernel.events().unwrap(), events_before);
}

#[test]
fn delegation_enforces_the_public_maximum_authority_chain_depth_without_mutation() {
    let fixture = fixture();
    let mut parent = fixture.kernel.root_lease_id().unwrap();
    let mut chain_ids = vec![parent.clone()];

    for depth in 2..=MAX_AUTHORITY_CHAIN_DEPTH {
        parent = delegate_child(
            &fixture,
            parent,
            0,
            &format!("agent-depth-{depth}"),
            Arc::new(
                InMemoryKeyCustody::generate(KeyId::new(format!("key-depth-{depth}")).unwrap())
                    .unwrap(),
            ),
            Capability::ReadFile("/data/reports".into()),
            ("fixture.read", "read-v1"),
        );
        chain_ids.push(parent.clone());
    }

    let leaf_manifest = manifest(
        vec![Capability::ReadFile("/data/reports".into())],
        vec![("fixture.read", "read-v1")],
    );
    let validated = fixture
        .kernel
        .validate_active_chain(&parent, Some(0), &leaf_manifest, fixture.now)
        .unwrap();
    assert_eq!(validated.chain.len(), MAX_AUTHORITY_CHAIN_DEPTH);
    let snapshot_before = AuthorityStateSnapshot::capture(&fixture.kernel, &chain_ids);
    let rejected_agent = aeon_agent_runtime::AgentId::new("agent-too-deep").unwrap();

    let error = fixture
        .kernel
        .delegate(
            DelegationRequest {
                parent_lease_id: parent,
                expected_parent_generation: 0,
                child_agent_id: rejected_agent.clone(),
                granted_authority: authority_set(vec![Capability::ReadFile(
                    "/data/reports".into(),
                )]),
                delegable_authority: authority_set(vec![Capability::ReadFile(
                    "/data/reports".into(),
                )]),
                capability_manifest: leaf_manifest,
                semantic_context_digest: digest("too-deep-context"),
                expires_at: fixture.now + Duration::minutes(30),
            },
            Arc::new(InMemoryKeyCustody::generate(KeyId::new("key-too-deep").unwrap()).unwrap()),
            fixture.now,
        )
        .unwrap_err();

    assert_eq!(error.code(), ErrorCode::DelegationInvalid);
    assert_eq!(
        AuthorityStateSnapshot::capture(&fixture.kernel, &chain_ids),
        snapshot_before
    );
    assert!(fixture
        .kernel
        .identity_certificate(&rejected_agent)
        .is_err());
}

#[derive(Debug, PartialEq, Eq)]
struct AuthorityStateSnapshot {
    root_lease_id: LeaseId,
    leases: Vec<(LeaseId, LeaseSnapshot)>,
    events: Vec<AuthorityEvent>,
}

impl AuthorityStateSnapshot {
    fn capture(kernel: &AuthorityKernel, lease_ids: &[LeaseId]) -> Self {
        Self {
            root_lease_id: kernel.root_lease_id().unwrap(),
            leases: lease_ids
                .iter()
                .map(|lease_id| (lease_id.clone(), kernel.lease_snapshot(lease_id).unwrap()))
                .collect(),
            events: kernel.events().unwrap(),
        }
    }
}

#[test]
fn revocation_returns_root_first_breadth_first_sorted_lease_ids() {
    let fixture = fixture();
    let root = fixture.kernel.root_lease_id().unwrap();
    let child_a = delegate_child(
        &fixture,
        root.clone(),
        0,
        "agent-child-a",
        Arc::new(InMemoryKeyCustody::generate(KeyId::new("key-child-a").unwrap()).unwrap()),
        Capability::ReadFile("/data/reports/a".into()),
        ("fixture.read", "read-v1"),
    );
    let child_b = delegate_child(
        &fixture,
        root.clone(),
        0,
        "agent-child-b",
        Arc::new(InMemoryKeyCustody::generate(KeyId::new("key-child-b").unwrap()).unwrap()),
        Capability::ReadFile("/data/reports/b".into()),
        ("fixture.read", "read-v1"),
    );
    let grandchild_a = delegate_child(
        &fixture,
        child_a.clone(),
        0,
        "agent-grandchild-a",
        Arc::new(InMemoryKeyCustody::generate(KeyId::new("key-grandchild-a").unwrap()).unwrap()),
        Capability::ReadFile("/data/reports/a/final".into()),
        ("fixture.read", "read-v1"),
    );
    let grandchild_b = delegate_child(
        &fixture,
        child_b.clone(),
        0,
        "agent-grandchild-b",
        Arc::new(InMemoryKeyCustody::generate(KeyId::new("key-grandchild-b").unwrap()).unwrap()),
        Capability::ReadFile("/data/reports/b/final".into()),
        ("fixture.read", "read-v1"),
    );
    let mut branches = [(child_a, grandchild_a), (child_b, grandchild_b)];
    branches.sort_by(|left, right| left.0.cmp(&right.0));
    let expected = std::iter::once(root.clone())
        .chain(branches.iter().map(|(child, _)| child.clone()))
        .chain(branches.iter().map(|(_, grandchild)| grandchild.clone()))
        .collect::<Vec<_>>();

    let affected = fixture
        .kernel
        .revoke(&root, 0, "deterministic cascade", fixture.now)
        .unwrap();

    assert_eq!(affected, expected);
    let event_ids = fixture
        .kernel
        .events()
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == AuthorityEventKind::LeaseRevoked)
        .map(|event| event.lease_id)
        .collect::<Vec<_>>();
    assert_eq!(event_ids, expected);
}

#[test]
fn expiration_candidates_and_events_are_sorted_by_lease_id() {
    let fixture = fixture();
    let root = fixture.kernel.root_lease_id().unwrap();
    let child_a = delegate_child(
        &fixture,
        root.clone(),
        0,
        "agent-expiring-a",
        Arc::new(InMemoryKeyCustody::generate(KeyId::new("key-expiring-a").unwrap()).unwrap()),
        Capability::ReadFile("/data/reports/a".into()),
        ("fixture.read", "read-v1"),
    );
    let child_b = delegate_child(
        &fixture,
        root,
        0,
        "agent-expiring-b",
        Arc::new(InMemoryKeyCustody::generate(KeyId::new("key-expiring-b").unwrap()).unwrap()),
        Capability::ReadFile("/data/reports/b".into()),
        ("fixture.read", "read-v1"),
    );
    let mut expected = vec![child_a, child_b];
    expected.sort();

    let expired = fixture
        .kernel
        .refresh_expirations(fixture.now + Duration::minutes(31))
        .unwrap();

    assert_eq!(expired, expected);
    let event_ids = fixture
        .kernel
        .events()
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == AuthorityEventKind::LeaseExpired)
        .map(|event| event.lease_id)
        .collect::<Vec<_>>();
    assert_eq!(event_ids, expected);
}

#[test]
fn full_capability_manifest_is_checked_at_chain_validation() {
    let fixture = fixture();
    let root = fixture.kernel.root_lease_id().unwrap();
    let mut mutations = Vec::new();
    let mut changed = fixture.root_manifest.clone();
    changed.model_manifest_digest = digest("different-model");
    mutations.push(changed);
    let mut changed = fixture.root_manifest.clone();
    changed.approved_tools[0].tool_manifest_digest = digest("substituted-tool");
    mutations.push(changed);
    let mut changed = fixture.root_manifest.clone();
    changed.permissions.capabilities = vec![Capability::MemoryPreview];
    mutations.push(changed);
    let mut changed = fixture.root_manifest.clone();
    changed.runtime_config_digest = digest("different-runtime");
    mutations.push(changed);
    let mut changed = fixture.root_manifest.clone();
    changed.tool_registry_root_digest = digest("different-registry");
    mutations.push(changed);

    for substituted in mutations {
        let error = fixture
            .kernel
            .validate_active_chain(&root, Some(0), &substituted, fixture.now)
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::CapabilityManifestMismatch);
    }
}

#[test]
fn authority_events_and_debug_snapshots_never_persist_bearer_tokens() {
    let fixture = fixture();
    let root = fixture.kernel.root_lease_id().unwrap();
    fixture.kernel.pause(&root, 0, fixture.now).unwrap();
    fixture.kernel.resume(&root, 1, fixture.now).unwrap();
    let events = fixture.kernel.events().unwrap();
    assert!(events
        .iter()
        .any(|event| event.kind == AuthorityEventKind::LeasePaused));
    assert!(events
        .iter()
        .any(|event| event.kind == AuthorityEventKind::LeaseResumed));
    let evidence = format!("{:?}{:?}", fixture.kernel, events).to_ascii_lowercase();
    assert!(!evidence.contains("capabilitytoken"));
    assert!(!evidence.contains("bearer"));
    assert!(!evidence.contains("signing_key"));
}
