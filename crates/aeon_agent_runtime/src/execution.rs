use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[cfg(test)]
use std::panic::{catch_unwind, AssertUnwindSafe};

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier};
use nexus::{Capability, CapabilityToken, HypervisorConfig, NexusHypervisor, ToolOutput};
use serde_json::Value;

use crate::{
    canonical_digest, ActionCertificate, ActionTarget, AgentId, AuthorityKernel, AuthoritySet,
    AuthorizationId, AuthorizationRecord, AuthorizationState, Budget, CanonicalAction,
    CanonicalJson, CapabilityManifest, CertificateId, Digest, ErrorCode, InMemoryMissionStore,
    KeyCustody, LeaseId, MissionEnvelope, RuntimeError, SemanticContext, SemanticScope,
    SignatureBytes, ToolId, ToolRegistry,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExecutionPosition {
    BeforeNexus,
    Started,
}

#[derive(Debug)]
pub(crate) struct PositionedExecutionError {
    error: RuntimeError,
    position: ExecutionPosition,
}

impl PositionedExecutionError {
    fn before_nexus(error: RuntimeError) -> Self {
        Self {
            error,
            position: ExecutionPosition::BeforeNexus,
        }
    }

    fn started(error: RuntimeError) -> Self {
        Self {
            error,
            position: ExecutionPosition::Started,
        }
    }

    pub(crate) fn code(&self) -> ErrorCode {
        self.error.code()
    }

    pub(crate) fn position(&self) -> ExecutionPosition {
        self.position
    }

    pub(crate) fn into_runtime_error(self) -> RuntimeError {
        self.error
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct ExecutionTestHooks {
    pub(crate) after_authorization_consumed_under_guard:
        Option<Arc<dyn Fn() + Send + Sync + 'static>>,
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
            target: ActionTarget::new(proposal_tool_id.as_str())?,
            normalized_parameters: CanonicalJson::new(arguments.clone()),
            semantic_scope: SemanticScope::Mission,
        };
        let action_ref = canonical_action.action_ref()?;
        let concrete_input_digest = canonical_digest("aeon-concrete-input-v1", arguments)?;
        let authorization_id = AuthorizationId::new(format!("auth-{}", uuid::Uuid::new_v4()))?;
        let certificate_id = CertificateId::new(format!("cert-{}", uuid::Uuid::new_v4()))?;
        let expires_at = std::cmp::min(
            now + chrono::Duration::minutes(5),
            lease_snapshot.certificate.expires_at,
        );
        let mut certificate = ActionCertificate {
            certificate_id,
            mission_id: mission.mission_id.clone(),
            agent_identity_digest: validated_authority.agent_identity_digest,
            authority_lease_id: lease_id.clone(),
            organization_version: mission.organization_version,
            policy_epoch: mission.policy_epoch,
            semantic_context_digest: current_context_digest,
            action_ref,
            tool_id: proposal_tool_id.clone(),
            tool_manifest_digest: current_manifest_digest,
            concrete_input_digest,
            authorization_record_id: authorization_id,
            granted_uses: 1,
            authorization_generation: 0,
            issued_at: now,
            expires_at,
            signature: SignatureBytes::new(Vec::new()),
        };
        certificate.signature = key_custody.sign(&certificate.signing_payload()?)?;

        let authorization_record = AuthorizationRecord {
            record_id: certificate.authorization_record_id.clone(),
            action_ref,
            authority_chain: validated_authority.chain,
            total_budget: Budget { actions: 1 },
            remaining_budget: Budget { actions: 1 },
            state: AuthorizationState::Issued,
            stable_idempotency_key: format!("aeon-r1:{}", action_ref.digest().to_hex()),
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
        attempt_id: u64,
    ) -> Result<ToolOutput, PositionedExecutionError> {
        self.execute_inner(
            authorized,
            attempt_id,
            #[cfg(test)]
            None,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn execute_with_test_hooks(
        &self,
        authorized: AuthorizedExecution,
        attempt_id: u64,
        hooks: ExecutionTestHooks,
    ) -> Result<ToolOutput, PositionedExecutionError> {
        self.execute_inner(authorized, attempt_id, Some(&hooks))
            .await
    }

    async fn execute_inner(
        &self,
        authorized: AuthorizedExecution,
        attempt_id: u64,
        #[cfg(test)] hooks: Option<&ExecutionTestHooks>,
    ) -> Result<ToolOutput, PositionedExecutionError> {
        self.metrics.execution_port_call();

        // This full-chain validation plus single-use consumption is the R2
        // execution commit point. Control-plane transitions that linearize
        // before it reject; transitions after it affect later executions.
        let (registered_tool, live_manifest) = self
            .registry
            .resolve_with_capability_manifest(&authorized.tool_id, &authorized.capability_manifest)
            .map_err(PositionedExecutionError::before_nexus)?;
        if registered_tool
            .manifest_digest()
            .map_err(PositionedExecutionError::before_nexus)?
            != authorized.tool_manifest_digest
        {
            return Err(PositionedExecutionError::before_nexus(runtime_error(
                ErrorCode::ToolManifestMismatch,
                "tool manifest changed before Nexus execution",
            )));
        }

        let expected_leaf_generation = authorized
            .observed_generations
            .iter()
            .find(|(lease_id, _)| lease_id == &authorized.certificate.authority_lease_id)
            .map(|(_, generation)| *generation)
            .ok_or_else(|| {
                PositionedExecutionError::before_nexus(runtime_error(
                    ErrorCode::AuthorizationInvalid,
                    "authorization omitted the active lease generation",
                ))
            })?;
        let commit_now = Utc::now();
        let (hypervisor, tokens) = self
            .authority_kernel
            .commit_active_chain(
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
                        || validated.capability_manifest_digest
                            != live_manifest.canonical_digest()?
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
                    let (hypervisor, tokens) = self.store.consume_authorization_with(
                        &authorized.certificate.authorization_record_id,
                        authorized.certificate.authorization_generation,
                        || self.issue_tokens(&authorized.required_capabilities, token_validity),
                    )?;
                    #[cfg(test)]
                    if let Some(hook) = hooks
                        .and_then(|hooks| hooks.after_authorization_consumed_under_guard.as_ref())
                    {
                        catch_unwind(AssertUnwindSafe(|| hook())).map_err(|_| {
                            runtime_error(ErrorCode::Internal, "execution test hook panicked")
                        })?;
                    }
                    Ok((hypervisor, tokens))
                },
            )
            .map_err(PositionedExecutionError::before_nexus)?;

        // The single-use authorization is already irreversibly consumed. Only
        // after the authority read guard is released may evidence be appended.
        // If this append fails, the per-call hypervisor and tokens are dropped;
        // retry remains impossible because the authorization stays consumed.
        self.store
            .append_for_attempt(attempt_id, crate::MissionEventKind::AuthorizationConsumed)
            .map_err(PositionedExecutionError::before_nexus)?;

        let tool_definition = registered_tool.tool_definition();
        self.store
            .append_for_attempt(attempt_id, crate::MissionEventKind::ExecutionStarted)
            .map_err(PositionedExecutionError::before_nexus)?;
        self.metrics.nexus_execution();
        hypervisor
            .execute_tool_with_tokens(tool_definition, authorized.arguments, &tokens)
            .await
            .map_err(|_| {
                PositionedExecutionError::started(runtime_error(
                    ErrorCode::ExecutionFailed,
                    "Nexus execution failed",
                ))
            })
    }

    fn issue_tokens(
        &self,
        required_capabilities: &[Capability],
        token_validity: Duration,
    ) -> Result<(NexusHypervisor, Vec<CapabilityToken>), RuntimeError> {
        let hypervisor = NexusHypervisor::new(self.hypervisor_config.clone()).map_err(|_| {
            runtime_error(ErrorCode::ExecutionFailed, "Nexus initialization failed")
        })?;
        let mut tokens = Vec::with_capacity(required_capabilities.len());
        for capability in required_capabilities.iter().cloned() {
            let token = hypervisor
                .issue_token(capability, "aeon-r2", token_validity)
                .map_err(|_| {
                    runtime_error(ErrorCode::ExecutionFailed, "Nexus token issuance failed")
                })?;
            self.metrics.token_issued();
            tokens.push(token);
        }
        Ok((hypervisor, tokens))
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
