use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use nexus::{Capability, NexusHypervisor, ToolOutput};
use serde_json::Value;

use crate::{
    canonical_digest, ActionCertificate, AgentId, AgentLifecycle, AuthorityLeaseCertificate,
    AuthorizationId, AuthorizationRecord, AuthorizationState, Budget, CanonicalAction,
    CanonicalJson, CertificateId, Digest, ErrorCode, LeaseId, LeaseRecord, LeaseRef, LeaseState,
    MissionEnvelope, RuntimeError, SemanticContext, SemanticScope, SignatureBytes, ToolId,
    ToolRegistry,
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
pub(crate) struct RuntimeBinding {
    pub agent_id: AgentId,
    pub lifecycle: AgentLifecycle,
    pub lease_id: LeaseId,
    pub semantic_context_digest: Digest,
    pub bound_tools: Vec<(ToolId, Digest)>,
}

#[derive(Clone, Debug)]
pub(crate) struct AuthorizedExecution {
    pub tool_id: ToolId,
    pub arguments: Value,
    pub tool_manifest_digest: Digest,
    pub required_capabilities: Vec<Capability>,
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
        binding: &RuntimeBinding,
        lease_certificate: &AuthorityLeaseCertificate,
        lease_record: &LeaseRecord,
        current_context: &SemanticContext,
        registry: &ToolRegistry,
        proposal_tool_id: &ToolId,
        arguments: &Value,
        lease_verifying_key: &VerifyingKey,
        signing_key: &SigningKey,
        now: DateTime<Utc>,
    ) -> Result<(AuthorizedExecution, R1AuthorizationArtifact), RuntimeError> {
        if !mission.active || mission.expires_at <= now {
            return Err(runtime_error(
                ErrorCode::MissionInactive,
                "mission is inactive or expired",
            ));
        }
        if binding.lifecycle != AgentLifecycle::Active {
            return Err(runtime_error(
                ErrorCode::AgentInactive,
                "agent is not executable",
            ));
        }
        if lease_certificate.lease_id != binding.lease_id {
            return Err(runtime_error(
                ErrorCode::LeaseInactive,
                "runtime lease binding is missing",
            ));
        }
        if lease_record.lease_id != binding.lease_id
            || lease_record.state != LeaseState::Active
            || lease_certificate.expires_at <= now
        {
            return Err(runtime_error(
                ErrorCode::LeaseInactive,
                "authority lease is inactive or expired",
            ));
        }
        lease_certificate.verify_signature(lease_verifying_key)?;
        if lease_certificate.mission_id != mission.mission_id
            || lease_certificate.agent_id != binding.agent_id
            || lease_certificate.organization_version != mission.organization_version
            || lease_certificate.policy_epoch != mission.policy_epoch
        {
            return Err(runtime_error(
                ErrorCode::AuthorizationInvalid,
                "lease bindings do not match current runtime state",
            ));
        }

        let current_context_digest = current_context.canonical_digest()?;
        if current_context_digest != binding.semantic_context_digest
            || current_context_digest != lease_certificate.semantic_context_digest
        {
            return Err(runtime_error(
                ErrorCode::SemanticContextChanged,
                "semantic context changed after authorization",
            ));
        }
        if !mission.allowed_tools.contains(proposal_tool_id) {
            return Err(runtime_error(
                ErrorCode::ToolOutsideMission,
                "tool is outside the mission allowlist",
            ));
        }

        let registered_tool = registry.resolve(proposal_tool_id)?;
        let current_manifest_digest = registered_tool.manifest_digest()?;
        let authorized_manifest_digest = binding
            .bound_tools
            .iter()
            .find(|(tool_id, _)| tool_id == proposal_tool_id)
            .map(|(_, digest)| digest)
            .ok_or_else(|| {
                runtime_error(
                    ErrorCode::ToolManifestMismatch,
                    "tool was not bound at activation",
                )
            })?;
        if authorized_manifest_digest != &current_manifest_digest {
            return Err(runtime_error(
                ErrorCode::ToolManifestMismatch,
                "registered tool no longer matches its authorized manifest",
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
        if required_capabilities.iter().any(|capability| {
            !mission.allowed_capabilities.contains(capability)
                || !lease_certificate
                    .granted_authority
                    .capabilities
                    .contains(capability)
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
            binding.agent_id.clone(),
            binding.lease_id.clone(),
            action_ref,
            proposal_tool_id.clone(),
            current_manifest_digest,
            concrete_input_digest,
            authorization_id,
            now,
        );
        certificate.organization_version = mission.organization_version;
        certificate.policy_epoch = mission.policy_epoch;
        certificate.semantic_context_digest = current_context_digest;
        certificate.expires_at =
            std::cmp::min(certificate.expires_at, lease_certificate.expires_at);
        let certificate_signature = signing_key.sign(&certificate.signing_payload()?);
        certificate.signature = SignatureBytes::new(certificate_signature.to_bytes().to_vec());

        let lease_certificate_digest = canonical_digest(
            "aeon-authority-lease-certificate-record-v1",
            lease_certificate,
        )?;
        let authorization_record = AuthorizationRecord {
            record_id: certificate.authorization_record_id.clone(),
            action_ref,
            authority_chain: vec![LeaseRef {
                lease_id: binding.lease_id.clone(),
                certificate_digest: lease_certificate_digest,
            }],
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
            },
            R1AuthorizationArtifact {
                certificate,
                record: authorization_record,
            },
        ))
    }
}

pub(crate) struct NexusExecutionPort {
    hypervisor: NexusHypervisor,
    registry: ToolRegistry,
    metrics: Arc<MetricCounters>,
}

impl NexusExecutionPort {
    pub(crate) fn new(
        hypervisor: NexusHypervisor,
        registry: ToolRegistry,
        metrics: Arc<MetricCounters>,
    ) -> Self {
        Self {
            hypervisor,
            registry,
            metrics,
        }
    }

    pub(crate) async fn execute(
        &self,
        authorized: AuthorizedExecution,
        on_execution_started: impl FnOnce(),
    ) -> Result<ToolOutput, RuntimeError> {
        self.metrics.execution_port_call();

        // Re-resolve at the last trusted boundary to close the registry TOCTOU window.
        let registered_tool = self.registry.resolve(&authorized.tool_id)?;
        if registered_tool.manifest_digest()? != authorized.tool_manifest_digest {
            return Err(runtime_error(
                ErrorCode::ToolManifestMismatch,
                "tool manifest changed before Nexus execution",
            ));
        }

        let mut tokens = Vec::with_capacity(authorized.required_capabilities.len());
        for capability in authorized.required_capabilities {
            let token = self
                .hypervisor
                .issue_token(capability, "aeon-r1", TOKEN_VALIDITY)
                .map_err(|error| runtime_error(ErrorCode::ExecutionFailed, error.to_string()))?;
            self.metrics.token_issued();
            tokens.push(token);
        }

        let tool_definition = registered_tool.tool_definition();
        on_execution_started();
        self.metrics.nexus_execution();
        self.hypervisor
            .execute_tool_with_tokens(tool_definition, authorized.arguments, &tokens)
            .await
            .map_err(|error| runtime_error(ErrorCode::ExecutionFailed, error.to_string()))
    }
}

pub(crate) fn runtime_error(code: ErrorCode, message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(code, message)
}
