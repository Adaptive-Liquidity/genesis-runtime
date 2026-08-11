use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use nexus::Capability;

use crate::authority::{
    canonical_capabilities, AuthorityLeaseCertificate, AuthoritySet, CapabilityManifest,
    LeaseRecord, LeaseRef, LeaseState, SignatureBytes,
};
use crate::digest::{canonical_digest, Digest};
use crate::error::{ErrorCode, Result, RuntimeError};
use crate::identity::{AgentIdentityCertificate, KeyCustody};
use crate::ids::{AgentId, LeaseId};
use crate::mission::MissionEnvelope;

mod validation;

use validation::*;

/// Maximum supported root-to-leaf authority and identity chain depth.
/// The root certificate occupies depth one.
pub const MAX_AUTHORITY_CHAIN_DEPTH: usize = 32;

#[derive(Debug, Clone)]
pub struct RootLeaseRequest {
    pub mission: MissionEnvelope,
    pub agent_id: AgentId,
    pub granted_authority: AuthoritySet,
    pub delegable_authority: AuthoritySet,
    pub capability_manifest: CapabilityManifest,
    pub semantic_context_digest: Digest,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct DelegationRequest {
    pub parent_lease_id: LeaseId,
    pub expected_parent_generation: u64,
    pub child_agent_id: AgentId,
    pub granted_authority: AuthoritySet,
    pub delegable_authority: AuthoritySet,
    pub capability_manifest: CapabilityManifest,
    pub semantic_context_digest: Digest,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct RenewalRequest {
    pub lease_id: LeaseId,
    pub expected_generation: u64,
    pub granted_authority: AuthoritySet,
    pub delegable_authority: AuthoritySet,
    pub capability_manifest: CapabilityManifest,
    pub semantic_context_digest: Digest,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseSnapshot {
    pub certificate: AuthorityLeaseCertificate,
    pub record: LeaseRecord,
    pub manifest: CapabilityManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAuthority {
    pub leaf_lease_id: LeaseId,
    pub leaf_expires_at: DateTime<Utc>,
    pub agent_identity_digest: Digest,
    pub capability_manifest_digest: Digest,
    pub semantic_context_digest: Digest,
    pub chain: Vec<LeaseRef>,
    pub observed_generations: Vec<(LeaseId, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityEventKind {
    IdentityRegistered,
    LeaseIssued,
    LeaseDelegated,
    LeasePaused,
    LeaseResumed,
    LeaseRevoked,
    LeaseExpired,
    LeaseRenewed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityEvent {
    pub sequence: u64,
    pub lease_id: LeaseId,
    pub related_lease_id: Option<LeaseId>,
    pub kind: AuthorityEventKind,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct AuthorityKernel {
    inner: Arc<RwLock<AuthorityState>>,
}

struct AuthorityState {
    mission: MissionEnvelope,
    root_lease_id: LeaseId,
    identities: HashMap<AgentId, AgentIdentityCertificate>,
    custodians: HashMap<AgentId, Arc<dyn KeyCustody>>,
    leases: HashMap<LeaseId, LeaseEntry>,
    events: Vec<AuthorityEvent>,
}

#[derive(Clone)]
struct LeaseEntry {
    certificate: AuthorityLeaseCertificate,
    record: LeaseRecord,
    manifest: CapabilityManifest,
}

impl fmt::Debug for AuthorityKernel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner.read() {
            Ok(state) => formatter
                .debug_struct("AuthorityKernel")
                .field("mission_id", &state.mission.mission_id)
                .field("root_lease_id", &state.root_lease_id)
                .field("identity_count", &state.identities.len())
                .field("lease_count", &state.leases.len())
                .field("event_count", &state.events.len())
                .finish(),
            Err(_) => formatter
                .debug_struct("AuthorityKernel")
                .field("state", &"unavailable")
                .finish(),
        }
    }
}

impl AuthorityKernel {
    pub fn bootstrap(
        request: RootLeaseRequest,
        root_custody: Arc<dyn KeyCustody>,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        validate_root_request(&request, now)?;
        let root_identity = signed_identity(
            request.agent_id.clone(),
            root_custody.as_ref(),
            None,
            root_custody.as_ref(),
            now,
        )?;
        let identity_digest = root_identity.canonical_digest()?;
        let lease_id = new_lease_id()?;
        let certificate = signed_lease(
            LeaseDraft {
                lease_id: lease_id.clone(),
                mission_id: request.mission.mission_id.clone(),
                agent_id: request.agent_id.clone(),
                agent_identity_digest: identity_digest,
                parent_agent_id: None,
                parent_lease: None,
                renewed_from: None,
                organization_version: request.mission.organization_version,
                policy_epoch: request.mission.policy_epoch,
                granted_authority: request.granted_authority,
                delegable_authority: request.delegable_authority,
                capability_manifest_digest: request.capability_manifest.canonical_digest()?,
                semantic_context_digest: request.semantic_context_digest,
                issued_at: now,
                expires_at: request.expires_at,
            },
            identity_digest,
            root_custody.as_ref(),
        )?;
        let mut identities = HashMap::new();
        identities.insert(request.agent_id.clone(), root_identity);
        let mut custodians = HashMap::new();
        custodians.insert(request.agent_id, root_custody);
        let mut leases = HashMap::new();
        leases.insert(
            lease_id.clone(),
            LeaseEntry {
                certificate,
                record: LeaseRecord::active(lease_id.clone()),
                manifest: request.capability_manifest,
            },
        );
        let mut state = AuthorityState {
            mission: request.mission,
            root_lease_id: lease_id.clone(),
            identities,
            custodians,
            leases,
            events: Vec::new(),
        };
        push_event(
            &mut state,
            lease_id.clone(),
            None,
            AuthorityEventKind::IdentityRegistered,
            now,
        );
        push_event(
            &mut state,
            lease_id,
            None,
            AuthorityEventKind::LeaseIssued,
            now,
        );
        Ok(Self {
            inner: Arc::new(RwLock::new(state)),
        })
    }

    pub fn root_lease_id(&self) -> Result<LeaseId> {
        Ok(self.read_state()?.root_lease_id.clone())
    }

    pub fn identity_certificate(&self, agent_id: &AgentId) -> Result<AgentIdentityCertificate> {
        self.read_state()?
            .identities
            .get(agent_id)
            .cloned()
            .ok_or_else(|| authority_error(ErrorCode::IdentityInvalid, "agent identity not found"))
    }

    pub fn lease_snapshot(&self, lease_id: &LeaseId) -> Result<LeaseSnapshot> {
        let state = self.read_state()?;
        snapshot(state.leases.get(lease_id).ok_or_else(|| {
            authority_error(ErrorCode::LeaseInactive, "authority lease not found")
        })?)
    }

    pub fn events(&self) -> Result<Vec<AuthorityEvent>> {
        Ok(self.read_state()?.events.clone())
    }

    pub fn delegate(
        &self,
        request: DelegationRequest,
        child_custody: Arc<dyn KeyCustody>,
        now: DateTime<Utc>,
    ) -> Result<LeaseId> {
        let mut state = self.write_state()?;
        let parent = state
            .leases
            .get(&request.parent_lease_id)
            .cloned()
            .ok_or_else(|| authority_error(ErrorCode::LeaseInactive, "parent lease not found"))?;
        validate_active_record(&parent, Some(request.expected_parent_generation), now)?;
        let validated_parent = validate_chain(
            &state,
            &request.parent_lease_id,
            Some(request.expected_parent_generation),
            &parent.manifest,
            now,
        )?;
        if validated_parent.chain.len() >= MAX_AUTHORITY_CHAIN_DEPTH {
            return Err(authority_error(
                ErrorCode::DelegationInvalid,
                "delegation would exceed the maximum authority chain depth",
            ));
        }
        validate_delegation_request(&state, &parent, &request, now)?;
        if state.identities.contains_key(&request.child_agent_id) {
            return Err(authority_error(
                ErrorCode::IdentityInvalid,
                "child agent identity is already registered",
            ));
        }
        if state
            .identities
            .values()
            .any(|identity| identity.key_id == child_custody.key_id())
        {
            return Err(authority_error(
                ErrorCode::IdentityInvalid,
                "child key id is already bound to an agent",
            ));
        }
        let parent_custody = state
            .custodians
            .get(&parent.certificate.agent_id)
            .cloned()
            .ok_or_else(|| authority_error(ErrorCode::IdentityInvalid, "parent key unavailable"))?;
        let child_identity = signed_identity(
            request.child_agent_id.clone(),
            child_custody.as_ref(),
            Some(parent.certificate.agent_id.clone()),
            parent_custody.as_ref(),
            now,
        )?;
        let child_identity_digest = child_identity.canonical_digest()?;
        let parent_identity = state
            .identities
            .get(&parent.certificate.agent_id)
            .ok_or_else(|| {
                authority_error(ErrorCode::IdentityInvalid, "parent identity missing")
            })?;
        let parent_reference = lease_ref(&parent.certificate)?;
        let child_lease_id = new_lease_id()?;
        let child_certificate = signed_lease(
            LeaseDraft {
                lease_id: child_lease_id.clone(),
                mission_id: parent.certificate.mission_id.clone(),
                agent_id: request.child_agent_id.clone(),
                agent_identity_digest: child_identity_digest,
                parent_agent_id: Some(parent.certificate.agent_id.clone()),
                parent_lease: Some(parent_reference),
                renewed_from: None,
                organization_version: parent.certificate.organization_version,
                policy_epoch: parent.certificate.policy_epoch,
                granted_authority: request.granted_authority,
                delegable_authority: request.delegable_authority,
                capability_manifest_digest: request.capability_manifest.canonical_digest()?,
                semantic_context_digest: request.semantic_context_digest,
                issued_at: now,
                expires_at: request.expires_at,
            },
            parent_identity.canonical_digest()?,
            parent_custody.as_ref(),
        )?;
        state
            .identities
            .insert(request.child_agent_id.clone(), child_identity);
        state
            .custodians
            .insert(request.child_agent_id, child_custody);
        state.leases.insert(
            child_lease_id.clone(),
            LeaseEntry {
                certificate: child_certificate,
                record: LeaseRecord::active(child_lease_id.clone()),
                manifest: request.capability_manifest,
            },
        );
        push_event(
            &mut state,
            child_lease_id.clone(),
            Some(request.parent_lease_id.clone()),
            AuthorityEventKind::IdentityRegistered,
            now,
        );
        push_event(
            &mut state,
            child_lease_id.clone(),
            Some(request.parent_lease_id),
            AuthorityEventKind::LeaseDelegated,
            now,
        );
        Ok(child_lease_id)
    }

    pub fn validate_active_chain(
        &self,
        leaf_lease_id: &LeaseId,
        expected_leaf_generation: Option<u64>,
        current_manifest: &CapabilityManifest,
        now: DateTime<Utc>,
    ) -> Result<ValidatedAuthority> {
        let state = self.read_state()?;
        validate_chain(
            &state,
            leaf_lease_id,
            expected_leaf_generation,
            current_manifest,
            now,
        )
    }

    pub(crate) fn commit_active_chain<T>(
        &self,
        leaf_lease_id: &LeaseId,
        expected_leaf_generation: Option<u64>,
        current_manifest: &CapabilityManifest,
        now: DateTime<Utc>,
        commit: impl FnOnce(&ValidatedAuthority) -> Result<T>,
    ) -> Result<T> {
        let state = self.read_state()?;
        let validated = validate_chain(
            &state,
            leaf_lease_id,
            expected_leaf_generation,
            current_manifest,
            now,
        )?;
        commit(&validated)
    }

    pub fn pause(
        &self,
        lease_id: &LeaseId,
        expected_generation: u64,
        now: DateTime<Utc>,
    ) -> Result<LeaseRecord> {
        self.transition(
            lease_id,
            expected_generation,
            LeaseState::Active,
            LeaseState::Paused,
            AuthorityEventKind::LeasePaused,
            now,
        )
    }

    pub fn resume(
        &self,
        lease_id: &LeaseId,
        expected_generation: u64,
        now: DateTime<Utc>,
    ) -> Result<LeaseRecord> {
        self.transition(
            lease_id,
            expected_generation,
            LeaseState::Paused,
            LeaseState::Active,
            AuthorityEventKind::LeaseResumed,
            now,
        )
    }

    pub fn revoke(
        &self,
        lease_id: &LeaseId,
        expected_generation: u64,
        reason: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<Vec<LeaseId>> {
        let mut state = self.write_state()?;
        let record = state
            .leases
            .get(lease_id)
            .ok_or_else(|| authority_error(ErrorCode::LeaseInactive, "lease not found"))?
            .record
            .clone();
        require_generation(&record, expected_generation)?;
        if !matches!(record.state, LeaseState::Active | LeaseState::Paused) {
            return Err(authority_error(
                ErrorCode::LeaseInactive,
                "only active or paused leases may be revoked",
            ));
        }
        let reason = reason.into();
        let affected = descendants_including(&state, lease_id)?;
        for affected_id in &affected {
            let entry = state.leases.get_mut(affected_id).ok_or_else(|| {
                authority_error(ErrorCode::LeaseInactive, "descendant lease disappeared")
            })?;
            if matches!(entry.record.state, LeaseState::Active | LeaseState::Paused) {
                entry.record.state = LeaseState::Revoked;
                entry.record.generation += 1;
                entry.record.revoked_at = Some(now);
                entry.record.revocation_reason = Some(reason.clone());
                push_event(
                    &mut state,
                    affected_id.clone(),
                    (affected_id != lease_id).then(|| lease_id.clone()),
                    AuthorityEventKind::LeaseRevoked,
                    now,
                );
            }
        }
        Ok(affected)
    }

    pub fn refresh_expirations(&self, now: DateTime<Utc>) -> Result<Vec<LeaseId>> {
        let mut state = self.write_state()?;
        let due = state
            .leases
            .iter()
            .filter(|(_, entry)| {
                matches!(entry.record.state, LeaseState::Active | LeaseState::Paused)
                    && now >= entry.certificate.expires_at
            })
            .map(|(lease_id, _)| lease_id.clone())
            .collect::<Vec<_>>();
        let mut expired = Vec::new();
        for lease_id in due {
            let entry = state.leases.get_mut(&lease_id).ok_or_else(|| {
                authority_error(ErrorCode::LeaseInactive, "expiring lease disappeared")
            })?;
            if matches!(entry.record.state, LeaseState::Active | LeaseState::Paused) {
                entry.record.state = LeaseState::Expired;
                entry.record.generation += 1;
                expired.push(lease_id.clone());
                push_event(
                    &mut state,
                    lease_id.clone(),
                    None,
                    AuthorityEventKind::LeaseExpired,
                    now,
                );
                revoke_descendants(&mut state, &lease_id, "ancestor lease expired", now)?;
            }
        }
        Ok(expired)
    }

    pub fn renew(&self, request: RenewalRequest, now: DateTime<Utc>) -> Result<LeaseId> {
        let mut state = self.write_state()?;
        let old = state
            .leases
            .get(&request.lease_id)
            .cloned()
            .ok_or_else(|| authority_error(ErrorCode::LeaseInactive, "lease not found"))?;
        validate_active_record(&old, Some(request.expected_generation), now)?;
        validate_chain(
            &state,
            &request.lease_id,
            Some(request.expected_generation),
            &old.manifest,
            now,
        )?;
        validate_renewal_request(&state, &old, &request, now)?;
        let issuer_agent_id = old
            .certificate
            .parent_agent_id
            .clone()
            .unwrap_or_else(|| old.certificate.agent_id.clone());
        let issuer_identity = state.identities.get(&issuer_agent_id).ok_or_else(|| {
            authority_error(
                ErrorCode::IdentityInvalid,
                "renewal issuer identity missing",
            )
        })?;
        let issuer_custody = state
            .custodians
            .get(&issuer_agent_id)
            .cloned()
            .ok_or_else(|| {
                authority_error(ErrorCode::IdentityInvalid, "renewal key unavailable")
            })?;
        let new_lease_id = new_lease_id()?;
        let certificate = signed_lease(
            LeaseDraft {
                lease_id: new_lease_id.clone(),
                mission_id: old.certificate.mission_id.clone(),
                agent_id: old.certificate.agent_id.clone(),
                agent_identity_digest: old.certificate.agent_identity_digest,
                parent_agent_id: old.certificate.parent_agent_id.clone(),
                parent_lease: old.certificate.parent_lease.clone(),
                renewed_from: Some(lease_ref(&old.certificate)?),
                organization_version: old.certificate.organization_version,
                policy_epoch: old.certificate.policy_epoch,
                granted_authority: request.granted_authority,
                delegable_authority: request.delegable_authority,
                capability_manifest_digest: request.capability_manifest.canonical_digest()?,
                semantic_context_digest: request.semantic_context_digest,
                issued_at: now,
                expires_at: request.expires_at,
            },
            issuer_identity.canonical_digest()?,
            issuer_custody.as_ref(),
        )?;
        let old_entry = state.leases.get_mut(&request.lease_id).ok_or_else(|| {
            authority_error(ErrorCode::LeaseInactive, "renewed lease disappeared")
        })?;
        old_entry.record.state = LeaseState::Retired;
        old_entry.record.generation += 1;
        old_entry.record.renewed_by = Some(new_lease_id.clone());
        revoke_descendants(
            &mut state,
            &request.lease_id,
            "ancestor lease retired during renewal",
            now,
        )?;
        state.leases.insert(
            new_lease_id.clone(),
            LeaseEntry {
                certificate,
                record: LeaseRecord::active(new_lease_id.clone()),
                manifest: request.capability_manifest,
            },
        );
        if state.root_lease_id == request.lease_id {
            state.root_lease_id = new_lease_id.clone();
        }
        push_event(
            &mut state,
            new_lease_id.clone(),
            Some(request.lease_id),
            AuthorityEventKind::LeaseRenewed,
            now,
        );
        Ok(new_lease_id)
    }

    fn transition(
        &self,
        lease_id: &LeaseId,
        expected_generation: u64,
        expected_state: LeaseState,
        next_state: LeaseState,
        event: AuthorityEventKind,
        now: DateTime<Utc>,
    ) -> Result<LeaseRecord> {
        let mut state = self.write_state()?;
        let record = state
            .leases
            .get_mut(lease_id)
            .ok_or_else(|| authority_error(ErrorCode::LeaseInactive, "lease not found"))?;
        require_generation(&record.record, expected_generation)?;
        if record.record.state != expected_state || now >= record.certificate.expires_at {
            return Err(authority_error(
                ErrorCode::LeaseInactive,
                "lease state does not allow the requested transition",
            ));
        }
        record.record.state = next_state;
        record.record.generation += 1;
        let output = record.record.clone();
        push_event(&mut state, lease_id.clone(), None, event, now);
        Ok(output)
    }

    fn read_state(&self) -> Result<std::sync::RwLockReadGuard<'_, AuthorityState>> {
        self.inner
            .read()
            .map_err(|_| authority_error(ErrorCode::Internal, "authority state lock poisoned"))
    }

    fn write_state(&self) -> Result<std::sync::RwLockWriteGuard<'_, AuthorityState>> {
        self.inner
            .write()
            .map_err(|_| authority_error(ErrorCode::Internal, "authority state lock poisoned"))
    }
}

struct LeaseDraft {
    lease_id: LeaseId,
    mission_id: crate::ids::MissionId,
    agent_id: AgentId,
    agent_identity_digest: Digest,
    parent_agent_id: Option<AgentId>,
    parent_lease: Option<LeaseRef>,
    renewed_from: Option<LeaseRef>,
    organization_version: u64,
    policy_epoch: u64,
    granted_authority: AuthoritySet,
    delegable_authority: AuthoritySet,
    capability_manifest_digest: Digest,
    semantic_context_digest: Digest,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

fn signed_identity(
    agent_id: AgentId,
    subject_custody: &dyn KeyCustody,
    issuer_agent_id: Option<AgentId>,
    issuer_custody: &dyn KeyCustody,
    now: DateTime<Utc>,
) -> Result<AgentIdentityCertificate> {
    let mut identity = AgentIdentityCertificate::unsigned(
        agent_id,
        subject_custody.key_id(),
        subject_custody.verifying_key(),
        issuer_agent_id,
        issuer_custody.key_id(),
        now,
    );
    identity.signature = issuer_custody.sign(&identity.signing_payload()?)?;
    identity.verify_signature(&issuer_custody.verifying_key())?;
    Ok(identity)
}

fn signed_lease(
    draft: LeaseDraft,
    issuer_identity_digest: Digest,
    issuer_custody: &dyn KeyCustody,
) -> Result<AuthorityLeaseCertificate> {
    let mut certificate = AuthorityLeaseCertificate {
        lease_id: draft.lease_id,
        mission_id: draft.mission_id,
        agent_id: draft.agent_id,
        agent_identity_digest: draft.agent_identity_digest,
        parent_agent_id: draft.parent_agent_id,
        parent_lease: draft.parent_lease,
        renewed_from: draft.renewed_from,
        issuer_identity_digest,
        issuer_key_id: issuer_custody.key_id(),
        organization_version: draft.organization_version,
        policy_epoch: draft.policy_epoch,
        granted_authority: draft.granted_authority,
        delegable_authority: draft.delegable_authority,
        capability_manifest_digest: draft.capability_manifest_digest,
        semantic_context_digest: draft.semantic_context_digest,
        issued_at: draft.issued_at,
        expires_at: draft.expires_at,
        signature: SignatureBytes::new(Vec::new()),
    };
    certificate.signature = issuer_custody.sign(&certificate.signing_payload()?)?;
    certificate.verify_signature(&issuer_custody.verifying_key())?;
    Ok(certificate)
}

fn validate_root_request(request: &RootLeaseRequest, now: DateTime<Utc>) -> Result<()> {
    if !request.mission.is_usable_at(now)
        || request.expires_at <= now
        || request.expires_at > request.mission.expires_at
    {
        return Err(authority_error(
            ErrorCode::LeaseInactive,
            "root lease lifetime is outside the active mission",
        ));
    }
    validate_authority_sets(&request.granted_authority, &request.delegable_authority)?;
    if !authority_is_subset_of_capabilities(
        &request.granted_authority,
        &request.mission.allowed_capabilities,
    ) {
        return Err(authority_error(
            ErrorCode::CapabilityOutsideAuthority,
            "root authority exceeds the mission envelope",
        ));
    }
    validate_manifest(&request.capability_manifest, &request.granted_authority)?;
    if request
        .capability_manifest
        .approved_tools
        .iter()
        .any(|bound| {
            !request
                .mission
                .allowed_tools
                .iter()
                .any(|allowed| allowed == &bound.tool_id)
        })
    {
        return Err(authority_error(
            ErrorCode::ToolOutsideMission,
            "root manifest contains a tool outside the mission",
        ));
    }
    Ok(())
}

fn validate_delegation_request(
    state: &AuthorityState,
    parent: &LeaseEntry,
    request: &DelegationRequest,
    now: DateTime<Utc>,
) -> Result<()> {
    if request.expires_at <= now
        || request.expires_at > parent.certificate.expires_at
        || request.expires_at > state.mission.expires_at
    {
        return Err(authority_error(
            ErrorCode::DelegationInvalid,
            "child lease lifetime exceeds its parent or mission",
        ));
    }
    validate_authority_sets(&request.granted_authority, &request.delegable_authority)?;
    if !authority_is_subset_of(
        &request.granted_authority,
        &parent.certificate.delegable_authority,
    ) {
        return Err(authority_error(
            ErrorCode::DelegationInvalid,
            "child granted authority exceeds parent delegable authority",
        ));
    }
    validate_manifest(&request.capability_manifest, &request.granted_authority)?;
    validate_manifest_attenuation(&request.capability_manifest, &parent.manifest)?;
    Ok(())
}

fn validate_renewal_request(
    state: &AuthorityState,
    old: &LeaseEntry,
    request: &RenewalRequest,
    now: DateTime<Utc>,
) -> Result<()> {
    if request.expires_at <= now || request.expires_at > state.mission.expires_at {
        return Err(authority_error(
            ErrorCode::DelegationInvalid,
            "renewed lease lifetime is outside the mission",
        ));
    }
    if request.semantic_context_digest != old.certificate.semantic_context_digest {
        return Err(authority_error(
            ErrorCode::SemanticContextChanged,
            "renewal must preserve the exact semantic context digest",
        ));
    }
    validate_authority_sets(&request.granted_authority, &request.delegable_authority)?;
    if !authority_is_subset_of(
        &request.granted_authority,
        &old.certificate.granted_authority,
    ) || !authority_is_subset_of(
        &request.delegable_authority,
        &old.certificate.delegable_authority,
    ) {
        return Err(authority_error(
            ErrorCode::DelegationInvalid,
            "renewal cannot expand authority",
        ));
    }
    validate_manifest(&request.capability_manifest, &request.granted_authority)?;
    validate_manifest_attenuation(&request.capability_manifest, &old.manifest)?;
    if let Some(parent_ref) = &old.certificate.parent_lease {
        let parent = state.leases.get(&parent_ref.lease_id).ok_or_else(|| {
            authority_error(ErrorCode::DelegationInvalid, "renewal parent lease missing")
        })?;
        validate_active_record(parent, None, now)?;
        if request.expires_at > parent.certificate.expires_at {
            return Err(authority_error(
                ErrorCode::DelegationInvalid,
                "renewed child cannot outlive its parent",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_fail_closed_when_authority_state_lock_is_poisoned() {
        let lease_id = LeaseId::new("lease-poison-test").unwrap();
        let kernel = AuthorityKernel {
            inner: Arc::new(RwLock::new(AuthorityState {
                mission: MissionEnvelope {
                    mission_id: crate::ids::MissionId::new("mission-poison-test").unwrap(),
                    allowed_tools: Vec::new(),
                    allowed_capabilities: Vec::new(),
                    policy_epoch: 1,
                    organization_version: 1,
                    active: true,
                    expires_at: Utc::now() + chrono::Duration::minutes(1),
                    max_actions: 1,
                },
                root_lease_id: lease_id,
                identities: HashMap::new(),
                custodians: HashMap::new(),
                leases: HashMap::new(),
                events: Vec::new(),
            })),
        };
        let poisoned = Arc::clone(&kernel.inner);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poisoned.write().unwrap();
            panic!("poison authority state for fail-closed test");
        }));

        let error = kernel.events().unwrap_err();
        assert_eq!(error.code(), ErrorCode::Internal);
    }
}
