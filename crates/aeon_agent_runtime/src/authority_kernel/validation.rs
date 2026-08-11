use super::*;

pub(super) fn validate_chain(
    state: &AuthorityState,
    leaf_lease_id: &LeaseId,
    expected_leaf_generation: Option<u64>,
    current_manifest: &CapabilityManifest,
    now: DateTime<Utc>,
) -> Result<ValidatedAuthority> {
    let mut visited = HashSet::new();
    let mut chain_entries = Vec::new();
    let mut current_id = leaf_lease_id.clone();
    loop {
        if !visited.insert(current_id.clone()) {
            return Err(authority_error(
                ErrorCode::DelegationInvalid,
                "authority chain contains a cycle",
            ));
        }
        let entry = state.leases.get(&current_id).ok_or_else(|| {
            authority_error(
                ErrorCode::DelegationInvalid,
                "authority chain lease missing",
            )
        })?;
        let expected = (current_id == *leaf_lease_id)
            .then_some(expected_leaf_generation)
            .flatten();
        validate_active_record(entry, expected, now)?;
        validate_certificate_entry(state, entry)?;
        chain_entries.push((current_id.clone(), entry));
        match &entry.certificate.parent_lease {
            Some(parent) => {
                if chain_entries.len() >= MAX_AUTHORITY_CHAIN_DEPTH {
                    return Err(authority_error(
                        ErrorCode::DelegationInvalid,
                        "authority chain exceeds the maximum supported depth",
                    ));
                }
                current_id = parent.lease_id.clone();
            }
            None => break,
        }
    }
    chain_entries.reverse();
    for pair in chain_entries.windows(2) {
        validate_parent_child(pair[0].1, pair[1].1)?;
    }
    let (_, leaf) = chain_entries
        .last()
        .ok_or_else(|| authority_error(ErrorCode::DelegationInvalid, "authority chain is empty"))?;
    if leaf.manifest.canonical_digest()? != current_manifest.canonical_digest()? {
        return Err(authority_error(
            ErrorCode::CapabilityManifestMismatch,
            "current capability manifest does not match the lease",
        ));
    }
    let chain = chain_entries
        .iter()
        .map(|(_, entry)| lease_ref(&entry.certificate))
        .collect::<Result<Vec<_>>>()?;
    let observed_generations = chain_entries
        .iter()
        .map(|(lease_id, entry)| (lease_id.clone(), entry.record.generation))
        .collect();
    Ok(ValidatedAuthority {
        leaf_lease_id: leaf_lease_id.clone(),
        leaf_expires_at: leaf.certificate.expires_at,
        agent_identity_digest: leaf.certificate.agent_identity_digest,
        capability_manifest_digest: leaf.certificate.capability_manifest_digest,
        semantic_context_digest: leaf.certificate.semantic_context_digest,
        chain,
        observed_generations,
    })
}

fn validate_certificate_entry(state: &AuthorityState, entry: &LeaseEntry) -> Result<()> {
    let certificate = &entry.certificate;
    if certificate.mission_id != state.mission.mission_id
        || certificate.organization_version != state.mission.organization_version
        || certificate.policy_epoch != state.mission.policy_epoch
        || certificate.capability_manifest_digest != entry.manifest.canonical_digest()?
    {
        return Err(authority_error(
            ErrorCode::CapabilityManifestMismatch,
            "lease bindings differ from current mission or manifest",
        ));
    }
    let subject = state.identities.get(&certificate.agent_id).ok_or_else(|| {
        authority_error(ErrorCode::IdentityInvalid, "lease subject identity missing")
    })?;
    validate_identity_chain(state, &certificate.agent_id)?;
    if subject.canonical_digest()? != certificate.agent_identity_digest {
        return Err(authority_error(
            ErrorCode::IdentityInvalid,
            "lease subject identity digest mismatch",
        ));
    }
    let issuer_agent_id = certificate
        .parent_agent_id
        .as_ref()
        .unwrap_or(&certificate.agent_id);
    let issuer = state.identities.get(issuer_agent_id).ok_or_else(|| {
        authority_error(ErrorCode::IdentityInvalid, "lease issuer identity missing")
    })?;
    if issuer.canonical_digest()? != certificate.issuer_identity_digest
        || issuer.key_id != certificate.issuer_key_id
    {
        return Err(authority_error(
            ErrorCode::IdentityInvalid,
            "lease issuer identity binding mismatch",
        ));
    }
    certificate.verify_signature(&issuer.verifying_key()?)?;
    if let Some(renewed_from) = &certificate.renewed_from {
        let predecessor = state.leases.get(&renewed_from.lease_id).ok_or_else(|| {
            authority_error(
                ErrorCode::DelegationInvalid,
                "renewal predecessor lease missing",
            )
        })?;
        if renewed_from != &lease_ref(&predecessor.certificate)?
            || predecessor.certificate.agent_id != certificate.agent_id
            || predecessor.certificate.mission_id != certificate.mission_id
            || predecessor.record.state != LeaseState::Retired
            || predecessor.record.renewed_by.as_ref() != Some(&certificate.lease_id)
        {
            return Err(authority_error(
                ErrorCode::DelegationInvalid,
                "renewal predecessor binding is invalid",
            ));
        }
    }
    Ok(())
}

fn validate_identity_chain(state: &AuthorityState, leaf_agent_id: &AgentId) -> Result<()> {
    let mut current_agent_id = leaf_agent_id.clone();
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(current_agent_id.clone()) {
            return Err(authority_error(
                ErrorCode::IdentityInvalid,
                "agent identity chain contains a cycle",
            ));
        }
        let identity = state.identities.get(&current_agent_id).ok_or_else(|| {
            authority_error(ErrorCode::IdentityInvalid, "agent identity is missing")
        })?;
        match &identity.issuer_agent_id {
            Some(issuer_agent_id) => {
                if visited.len() >= MAX_AUTHORITY_CHAIN_DEPTH {
                    return Err(authority_error(
                        ErrorCode::IdentityInvalid,
                        "agent identity chain exceeds the maximum supported depth",
                    ));
                }
                let issuer = state.identities.get(issuer_agent_id).ok_or_else(|| {
                    authority_error(ErrorCode::IdentityInvalid, "identity issuer is missing")
                })?;
                if identity.issuer_key_id != issuer.key_id {
                    return Err(authority_error(
                        ErrorCode::IdentityInvalid,
                        "identity issuer key binding is invalid",
                    ));
                }
                identity.verify_signature(&issuer.verifying_key()?)?;
                current_agent_id = issuer_agent_id.clone();
            }
            None => {
                if identity.issuer_key_id != identity.key_id {
                    return Err(authority_error(
                        ErrorCode::IdentityInvalid,
                        "root identity is not self-issued",
                    ));
                }
                identity.verify_signature(&identity.verifying_key()?)?;
                return Ok(());
            }
        }
    }
}

fn validate_parent_child(parent: &LeaseEntry, child: &LeaseEntry) -> Result<()> {
    let parent_ref = child.certificate.parent_lease.as_ref().ok_or_else(|| {
        authority_error(
            ErrorCode::DelegationInvalid,
            "child parent reference missing",
        )
    })?;
    if parent_ref != &lease_ref(&parent.certificate)?
        || child.certificate.parent_agent_id.as_ref() != Some(&parent.certificate.agent_id)
        || child.certificate.expires_at > parent.certificate.expires_at
        || !authority_is_subset_of(
            &child.certificate.granted_authority,
            &parent.certificate.delegable_authority,
        )
    {
        return Err(authority_error(
            ErrorCode::DelegationInvalid,
            "child lease is not an attenuated exact child of its parent",
        ));
    }
    validate_authority_sets(
        &child.certificate.granted_authority,
        &child.certificate.delegable_authority,
    )?;
    validate_manifest_attenuation(&child.manifest, &parent.manifest)
}

pub(super) fn validate_active_record(
    entry: &LeaseEntry,
    expected_generation: Option<u64>,
    now: DateTime<Utc>,
) -> Result<()> {
    if let Some(expected) = expected_generation {
        require_generation(&entry.record, expected)?;
    }
    if entry.record.state != LeaseState::Active || now >= entry.certificate.expires_at {
        return Err(authority_error(
            ErrorCode::LeaseInactive,
            "authority chain contains an inactive or expired lease",
        ));
    }
    Ok(())
}

pub(super) fn validate_authority_sets(
    granted: &AuthoritySet,
    delegable: &AuthoritySet,
) -> Result<()> {
    if granted
        .capabilities
        .iter()
        .chain(&delegable.capabilities)
        .any(|capability| capability == &Capability::All)
    {
        return Err(authority_error(
            ErrorCode::CapabilityAllForbidden,
            "Capability::All is forbidden in authority leases",
        ));
    }
    if !authority_is_subset_of(delegable, granted) {
        return Err(authority_error(
            ErrorCode::DelegationInvalid,
            "delegable authority exceeds granted authority",
        ));
    }
    Ok(())
}

pub(super) fn validate_manifest(
    manifest: &CapabilityManifest,
    authority: &AuthoritySet,
) -> Result<()> {
    if manifest.version != 1 {
        return Err(authority_error(
            ErrorCode::CapabilityManifestMismatch,
            "unsupported capability manifest version",
        ));
    }
    if canonical_capabilities(&manifest.permissions.capabilities)?
        != canonical_capabilities(&authority.capabilities)?
    {
        return Err(authority_error(
            ErrorCode::CapabilityManifestMismatch,
            "manifest permissions do not equal granted authority",
        ));
    }
    let mut tools = HashMap::new();
    for tool in &manifest.approved_tools {
        if tools
            .insert(tool.tool_id.clone(), tool.tool_manifest_digest)
            .is_some()
        {
            return Err(authority_error(
                ErrorCode::CapabilityManifestMismatch,
                "manifest contains duplicate tool bindings",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_manifest_attenuation(
    child: &CapabilityManifest,
    parent: &CapabilityManifest,
) -> Result<()> {
    if child.model_manifest_digest != parent.model_manifest_digest
        || child.runtime_config_digest != parent.runtime_config_digest
        || child.tool_registry_root_digest != parent.tool_registry_root_digest
        || child.approved_tools.iter().any(|child_tool| {
            !parent
                .approved_tools
                .iter()
                .any(|parent_tool| parent_tool == child_tool)
        })
    {
        return Err(authority_error(
            ErrorCode::CapabilityManifestMismatch,
            "child capability manifest is not attenuated from its parent",
        ));
    }
    Ok(())
}

pub(super) fn authority_is_subset_of(child: &AuthoritySet, parent: &AuthoritySet) -> bool {
    authority_is_subset_of_capabilities(child, &parent.capabilities)
}

pub(super) fn authority_is_subset_of_capabilities(
    child: &AuthoritySet,
    parent: &[Capability],
) -> bool {
    child
        .capabilities
        .iter()
        .all(|requested| parent.iter().any(|granted| requested.is_subset_of(granted)))
}

pub(super) fn require_generation(record: &LeaseRecord, expected_generation: u64) -> Result<()> {
    if record.generation != expected_generation {
        return Err(authority_error(
            ErrorCode::LeaseGenerationMismatch,
            "lease generation does not match the expected value",
        ));
    }
    Ok(())
}

pub(super) fn lease_ref(certificate: &AuthorityLeaseCertificate) -> Result<LeaseRef> {
    Ok(LeaseRef {
        lease_id: certificate.lease_id.clone(),
        certificate_digest: canonical_digest(
            "aeon-authority-lease-certificate-record-v2",
            certificate,
        )?,
    })
}

pub(super) fn new_lease_id() -> Result<LeaseId> {
    LeaseId::new(format!("lease-{}", uuid::Uuid::new_v4()))
}

pub(super) fn snapshot(entry: &LeaseEntry) -> Result<LeaseSnapshot> {
    Ok(LeaseSnapshot {
        certificate: entry.certificate.clone(),
        record: entry.record.clone(),
        manifest: entry.manifest.clone(),
    })
}

pub(super) fn descendants_including(
    state: &AuthorityState,
    root: &LeaseId,
) -> Result<Vec<LeaseId>> {
    if !state.leases.contains_key(root) {
        return Err(authority_error(ErrorCode::LeaseInactive, "lease not found"));
    }
    let mut result = vec![root.clone()];
    let mut index = 0;
    while index < result.len() {
        let parent = result[index].clone();
        for (lease_id, entry) in &state.leases {
            if entry
                .certificate
                .parent_lease
                .as_ref()
                .is_some_and(|reference| reference.lease_id == parent)
                && !result.contains(lease_id)
            {
                result.push(lease_id.clone());
            }
        }
        index += 1;
    }
    Ok(result)
}

pub(super) fn revoke_descendants(
    state: &mut AuthorityState,
    root: &LeaseId,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<()> {
    let descendants = descendants_including(state, root)?;
    for lease_id in descendants.into_iter().skip(1) {
        let entry = state.leases.get_mut(&lease_id).ok_or_else(|| {
            authority_error(ErrorCode::LeaseInactive, "descendant lease disappeared")
        })?;
        if matches!(entry.record.state, LeaseState::Active | LeaseState::Paused) {
            entry.record.state = LeaseState::Revoked;
            entry.record.generation += 1;
            entry.record.revoked_at = Some(now);
            entry.record.revocation_reason = Some(reason.to_owned());
            push_event(
                state,
                lease_id,
                Some(root.clone()),
                AuthorityEventKind::LeaseRevoked,
                now,
            );
        }
    }
    Ok(())
}

pub(super) fn push_event(
    state: &mut AuthorityState,
    lease_id: LeaseId,
    related_lease_id: Option<LeaseId>,
    kind: AuthorityEventKind,
    occurred_at: DateTime<Utc>,
) {
    state.events.push(AuthorityEvent {
        sequence: state.events.len() as u64 + 1,
        lease_id,
        related_lease_id,
        kind,
        occurred_at,
    });
}

pub(super) fn authority_error(code: ErrorCode, message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(code, message)
}
