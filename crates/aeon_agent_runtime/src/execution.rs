use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier};
use nexus::{Capability, HypervisorConfig, NexusHypervisor, ToolOutput};
use serde_json::Value;

use crate::{
    canonical_digest, ActionCertificate, AgentId, AuthorityKernel, AuthoritySet, AuthorizationId,
    AuthorizationRecord, AuthorizationState, Budget, CanonicalAction, CanonicalJson,
    CapabilityManifest, CertificateId, Digest, ErrorCode, InMemoryMissionStore, KeyCustody,
    LeaseId, MissionEnvelope, RuntimeError, SemanticContext, SemanticScope, ToolId, ToolRegistry,
};

const TOKEN_VALIDITY: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct R1Metrics {
    pub model_calls: u64,
    pub protocol_gate_calls: u64,
    pub action_gate_calls: u64,
    pub execution_port_calls: u64,
    pub token_issues: u64,
    pub nexus_executions: u64,
}

#[derive(Debug, Default)]
pub(crate) struct MetricCounters {
    model_calls: AtomicU64,
    protocol_gate_calls: AtomicU64,
    action_gate_calls: AtomicU64,
    execution_port_calls: AtomicU64,
    token_issues: AtomicU64,
    nexus_executions: AtomicU64,
}

impl MetricCounters {
    pub(crate) fn model_call(&self) {
        self.model_calls.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn protocol_gate_call(&self) {
        self.protocol_gate_calls.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn action_gate_call(&self) {
        self.action_gate_calls.fetch_add(1, Ordering::Relaxed);
    }

    fn execution_port_call(&self) {
        self.execution_port_calls.fetch_add(1, Ordering::Relaxed);
    }

    fn token_issued(&self) {
        self.token_issues.fetch_add(1, Ordering::Relaxed);
    }

    fn nexus_execution(&self) {
        self.nexus_executions.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> R1Metrics {
        R1Metrics {
            model_calls: self.model_calls.load(Ordering::Relaxed),
            protocol_gate_calls: self.protocol_gate_calls.load(Ordering::Relaxed),
            action_gate_calls: self.action_gate_calls.load(Ordering::Relaxed),
            execution_port_calls: self.execution_port_calls.load(Ordering::Relaxed),
            token_issues: self.token_issues.load(Ordering::Relaxed),
            nexus_executions: self.nexus_executions.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AuthorizedExecution {
    pub tool_id: ToolId,
    pub arguments: Value,
    pub tool_manifest_digest: Digest,
    pub required_capabilities: Vec<Capability>,
    pub capability_manifest: CapabilityManifest,
    pub certificate: ActionCertificate,
    pub observed_generations: Vec<(LeaseId, u64)>,
}

#[derive(Clone, Debug)]
pub(crate) struct R1AuthorizationArtifact {
    pub certificate: ActionCertificate,
    pub record: AuthorizationRecord,
}

#[derive(Debug, Default)]
pub struct ActionGate;

impl ActionGate {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authorize(
        &self,
        mission: &MissionEnvelope,
        agent_id: &AgentId,
        authority_kernel: &AuthorityKernel,
        lease_id: &LeaseId,
        current_context: &SemanticContext,
        registry: &ToolRegistry,
        proposal_tool_id: &ToolId,
        arguments: &Value,
        key_custody: &dyn KeyCustody,
        now: DateTime<Utc>,
    ) -> Result<(AuthorizedExecution, R1AuthorizationArtifact), RuntimeError> {
        if !mission.active || mission.expires_at <= now {
            return Err(runtime_error(
                ErrorCode::MissionInactive,
                "mission is inactive or expired",
            ));
        }
        if !mission.allowed_tools.contains(proposal_tool_id) {
            return Err(runtime_error(
                ErrorCode::ToolOutsideMission,
                "tool is outside the mission allowlist",
            ));
        }

        let lease_snapshot = authority_kernel.lease_snapshot(lease_id)?;
        let (registered_tool, live_manifest) = registry
            .resolve_with_capability_manifest(proposal_tool_id, &lease_snapshot.manifest)?;
        let current_manifest_digest = registered_tool.manifest_digest()?;
        let authorized_manifest_digest = lease_snapshot
            .manifest
            .approved_tools
            .iter()
            .find(|bound| &bound.tool_id == proposal_tool_id)
            .map(|bound| bound.tool_manifest_digest)
            .ok_or_else(|| {
                runtime_error(
                    ErrorCode::ToolManifestMismatch,
                    "tool was not bound at activation",
                )
            })?;
        if authorized_manifest_digest != current_manifest_digest {
            return Err(runtime_error(
                ErrorCode::ToolManifestMismatch,
                "registered tool no longer matches its authorized manifest",
            ));
        }

        let validated_authority = authority_kernel.validate_active_chain(
            lease_id,
            Some(lease_snapshot.record.generation),
            &live_manifest,
            now,
        )?;
        if lease_snapshot.certificate.agent_id != *agent_id
            || lease_snapshot.certificate.mission_id != mission.mission_id
            || lease_snapshot.certificate.organization_version != mission.organization_version
            || lease_snapshot.certificate.policy_epoch != mission.policy_epoch
        {
            return Err(runtime_error(
                ErrorCode::AuthorizationInvalid,
                "active authority does not match the runtime binding",
            ));
        }

        let current_context_digest = current_context.canonical_digest()?;
        if current_context_digest != validated_authority.semantic_context_digest {
            return Err(runtime_error(
                ErrorCode::SemanticContextChanged,
                "semantic context changed after authority issuance",
            ));
        }

        registered_tool.validate_input(arguments)?;
        let required_capabilities = registered_tool.manifest().required_capabilities.clone();
        if required_capabilities
            .iter()
            .any(|capability| capability == &Capability::All)
        {
            return Err(runtime_error(
                ErrorCode::CapabilityAllForbidden,
                "Capability::All is forbidden for synthesized agents",
            ));
        }
        let mission_authority = AuthoritySet::new(mission.allowed_capabilities.clone())?;
        if required_capabilities.iter().any(|capability| {
            !mission_authority.covers(capability)
                || !lease_snapshot
                    .certificate
                    .granted_authority
                    .covers(capability)
        }) {
            return Err(runtime_error(
                ErrorCode::CapabilityOutsideAuthority,
                "tool capability is outside granted mission authority",
            ));
        }

        let canonical_action = CanonicalAction {
            mission_id: mission.mission_id.clone(),
            effect_kind: registered_tool.manifest().effect_class,
            target: proposal_tool_id.as_str().to_owned(),
            normalized_parameters: CanonicalJson::new(arguments.clone()),
            semantic_scope: SemanticScope::Mission,
        };
        let action_ref = canonical_action.action_ref()?;
        let concrete_input_digest = canonical_digest("aeon-concrete-input-v1", arguments)?;
        let authorization_id = AuthorizationId::new(format!("auth-{}", uuid::Uuid::new_v4()))?;
        let certificate_id = CertificateId::new(format!("cert-{}", uuid::Uuid::new_v4()))?;
        let mut certificate = ActionCertificate::unsigned_fixture(
            certificate_id,
            mission.mission_id.clone(),
            agent_id.clone(),
            lease_id.clone(),
            action_ref,
            proposal_tool_id.clone(),
            current_manifest_digest,
            concrete_input_digest,
            authorization_id,
            now,
        );
        certificate.agent_identity_digest = validated_authority.agent_identity_digest;
        certificate.organization_version = mission.organization_version;
        certificate.policy_epoch = mission.policy_epoch;
        certificate.semantic_context_digest = current_context_digest;
        certificate.expires_at = std::cmp::min(
            certificate.expires_at,
            lease_snapshot.certificate.expires_at,
        );
        certificate.signature = key_custody.sign(&certificate.signing_payload()?)?;

        let authorization_record = AuthorizationRecord {
            record_id: certificate.authorization_record_id.clone(),
            action_ref,
            authority_chain: validated_authority.chain,
            total_budget: Budget { actions: 1 },
            remaining_budget: Budget { actions: 1 },
            state: AuthorizationState::Issued,
            stable_idempotency_key: format!("aeon-r1:{:?}", action_ref.digest()),
            effect_class: canonical_action.effect_kind,
            generation: 0,
        };

        Ok((
            AuthorizedExecution {
                tool_id: proposal_tool_id.clone(),
                arguments: arguments.clone(),
                tool_manifest_digest: current_manifest_digest,
                required_capabilities,
                capability_manifest: live_manifest,
                certificate: certificate.clone(),
                observed_generations: validated_authority.observed_generations,
            },
            R1AuthorizationArtifact {
                certificate,
                record: authorization_record,
            },
        ))
    }
}

pub(crate) struct NexusExecutionPort {
    hypervisor_config: HypervisorConfig,
    registry: ToolRegistry,
    authority_kernel: AuthorityKernel,
    semantic_context: Arc<RwLock<SemanticContext>>,
    store: Arc<InMemoryMissionStore>,
    key_custody: Arc<dyn KeyCustody>,
    metrics: Arc<MetricCounters>,
}

impl NexusExecutionPort {
    pub(crate) fn new(
        hypervisor_config: HypervisorConfig,
        registry: ToolRegistry,
        authority_kernel: AuthorityKernel,
        semantic_context: Arc<RwLock<SemanticContext>>,
        store: Arc<InMemoryMissionStore>,
        key_custody: Arc<dyn KeyCustody>,
        metrics: Arc<MetricCounters>,
    ) -> Self {
        Self {
            hypervisor_config,
            registry,
            authority_kernel,
            semantic_context,
            store,
            key_custody,
            metrics,
        }
    }

    pub(crate) async fn execute(
        &self,
        authorized: AuthorizedExecution,
        on_authorization_consumed: impl FnOnce(),
        on_execution_started: impl FnOnce(),
    ) -> Result<ToolOutput, RuntimeError> {
        self.metrics.execution_port_call();

        // This full-chain validation plus single-use consumption is the R2
        // execution commit point. Control-plane transitions that linearize
        // before it reject; transitions after it affect later executions.
        let (registered_tool, live_manifest) = self.registry.resolve_with_capability_manifest(
            &authorized.tool_id,
            &authorized.capability_manifest,
        )?;
        if registered_tool.manifest_digest()? != authorized.tool_manifest_digest {
            return Err(runtime_error(
                ErrorCode::ToolManifestMismatch,
                "tool manifest changed before Nexus execution",
            ));
        }

        let expected_leaf_generation = authorized
            .observed_generations
            .iter()
            .find(|(lease_id, _)| lease_id == &authorized.certificate.authority_lease_id)
            .map(|(_, generation)| *generation)
            .ok_or_else(|| {
                runtime_error(
                    ErrorCode::AuthorizationInvalid,
                    "authorization omitted the active lease generation",
                )
            })?;
        let commit_now = Utc::now();
        let (hypervisor, tokens) = self.authority_kernel.commit_active_chain(
            &authorized.certificate.authority_lease_id,
            Some(expected_leaf_generation),
            &live_manifest,
            commit_now,
            |validated| {
                if validated.observed_generations != authorized.observed_generations
                    || validated.agent_identity_digest
                        != authorized.certificate.agent_identity_digest
                    || validated.semantic_context_digest
                        != authorized.certificate.semantic_context_digest
                    || validated.capability_manifest_digest != live_manifest.canonical_digest()?
                {
                    return Err(runtime_error(
                        ErrorCode::AuthorizationInvalid,
                        "live authority no longer matches the issued action certificate",
                    ));
                }
                let current_context_digest = self
                    .semantic_context
                    .read()
                    .map_err(|_| {
                        runtime_error(ErrorCode::Internal, "semantic context lock poisoned")
                    })?
                    .canonical_digest()?;
                if current_context_digest != validated.semantic_context_digest {
                    return Err(runtime_error(
                        ErrorCode::SemanticContextChanged,
                        "semantic context changed before Nexus entry",
                    ));
                }
                validate_action_certificate(
                    &authorized.certificate,
                    &authorized,
                    self.key_custody.as_ref(),
                    commit_now,
                )?;

                // Token issuance remains synchronous and inside the authority
                // read guard. Control-plane transitions therefore linearize
                // either before validation or after token minting and
                // single-use authorization consumption.
                let issue_now = Utc::now();
                let remaining_authority =
                    std::cmp::min(validated.leaf_expires_at, authorized.certificate.expires_at)
                        - issue_now;
                let token_validity = remaining_authority.to_std().map_err(|_| {
                    runtime_error(
                        ErrorCode::LeaseInactive,
                        "authority expired before Nexus token issuance",
                    )
                })?;
                let token_validity = std::cmp::min(TOKEN_VALIDITY, token_validity);
                if token_validity.is_zero() {
                    return Err(runtime_error(
                        ErrorCode::LeaseInactive,
                        "authority expired before Nexus token issuance",
                    ));
                }

                // Pinned Nexus has no public token-revocation API. A per-call
                // hypervisor confines its capability manager and bearer tokens
                // to this execution. Any error in this closure drops both.
                let hypervisor =
                    NexusHypervisor::new(self.hypervisor_config.clone()).map_err(|_| {
                        runtime_error(ErrorCode::ExecutionFailed, "Nexus initialization failed")
                    })?;
                let mut tokens = Vec::with_capacity(authorized.required_capabilities.len());
                for capability in authorized.required_capabilities.iter().cloned() {
                    let token = hypervisor
                        .issue_token(capability, "aeon-r2", token_validity)
                        .map_err(|_| {
                            runtime_error(ErrorCode::ExecutionFailed, "Nexus token issuance failed")
                        })?;
                    self.metrics.token_issued();
                    tokens.push(token);
                }

                self.store.consume_authorization(
                    &authorized.certificate.authorization_record_id,
                    authorized.certificate.authorization_generation,
                )?;
                on_authorization_consumed();
                Ok((hypervisor, tokens))
            },
        )?;

        let tool_definition = registered_tool.tool_definition();
        on_execution_started();
        self.metrics.nexus_execution();
        hypervisor
            .execute_tool_with_tokens(tool_definition, authorized.arguments, &tokens)
            .await
            .map_err(|_| runtime_error(ErrorCode::ExecutionFailed, "Nexus execution failed"))
    }
}

fn validate_action_certificate(
    certificate: &ActionCertificate,
    authorized: &AuthorizedExecution,
    key_custody: &dyn KeyCustody,
    now: DateTime<Utc>,
) -> Result<(), RuntimeError> {
    if now >= certificate.expires_at
        || certificate.tool_id != authorized.tool_id
        || certificate.tool_manifest_digest != authorized.tool_manifest_digest
        || certificate.concrete_input_digest
            != canonical_digest("aeon-concrete-input-v1", &authorized.arguments)?
    {
        return Err(runtime_error(
            ErrorCode::AuthorizationInvalid,
            "action certificate is expired or does not bind the execution request",
        ));
    }
    let signature_bytes = <[u8; 64]>::try_from(certificate.signature.as_bytes()).map_err(|_| {
        runtime_error(
            ErrorCode::AuthorizationInvalid,
            "action certificate signature must contain exactly 64 bytes",
        )
    })?;
    let signature = Signature::from_bytes(&signature_bytes);
    key_custody
        .verifying_key()
        .verify(&certificate.signing_payload()?, &signature)
        .map_err(|_| {
            runtime_error(
                ErrorCode::AuthorizationInvalid,
                "action certificate signature verification failed",
            )
        })
}

pub(crate) fn runtime_error(code: ErrorCode, message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(code, message)
}

#[cfg(test)]
mod tests;
