use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use nexus::{Capability, HypervisorConfig, NexusHypervisor, ToolOutput};
use rand::rngs::OsRng;

use crate::execution::{
    runtime_error, ActionGate, MetricCounters, NexusExecutionPort, RuntimeBinding,
};
use crate::{
    canonical_digest, resolved_system_instruction, ActionCertificate, AgentId, AgentLifecycle,
    AgentMessage, AgentSpec, AuthorityLeaseCertificate, AuthoritySet, AuthorizationRecord,
    BoundTool, CapabilityManifest, ContextResolver, ErrorCode, FinalResult, InMemoryMissionStore,
    LeaseId, LeaseRecord, MissionEnvelope, MissionEventKind, ModelClient, ModelRequest,
    PermissionSet, ProtocolGate, RegisteredTool, RuntimeError, SemanticContext, SignatureBytes,
    ToolRegistry,
};

pub use crate::execution::R1Metrics;

#[derive(Clone, Debug)]
pub enum RunOutcome {
    Executed(Box<ToolOutput>),
    Final(FinalResult),
}

pub struct R1Runtime {
    mission: MissionEnvelope,
    agent_id: AgentId,
    spec: AgentSpec,
    model: Arc<dyn ModelClient>,
    registry: ToolRegistry,
    semantic_context: RwLock<SemanticContext>,
    runtime_binding: RuntimeBinding,
    lease_certificate: AuthorityLeaseCertificate,
    lease_record: LeaseRecord,
    lease_verifying_key: VerifyingKey,
    action_signing_key: SigningKey,
    protocol_gate: ProtocolGate,
    action_gate: ActionGate,
    execution_port: NexusExecutionPort,
    metrics: Arc<MetricCounters>,
    store: InMemoryMissionStore,
    action_certificates: Mutex<Vec<ActionCertificate>>,
    steps_consumed: AtomicU64,
    actions_consumed: AtomicU64,
}

impl fmt::Debug for R1Runtime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("R1Runtime")
            .field("mission_id", &self.mission.mission_id)
            .field("agent_id", &self.agent_id)
            .field("metrics", &self.metrics())
            .finish_non_exhaustive()
    }
}

impl R1Runtime {
    pub fn bootstrap(
        mission: MissionEnvelope,
        agent_id: AgentId,
        spec: AgentSpec,
        model: Arc<dyn ModelClient>,
        registry: ToolRegistry,
        context_version: u64,
    ) -> Result<Self, RuntimeError> {
        let now = Utc::now();
        if !mission.active || mission.expires_at <= now {
            return Err(runtime_error(
                ErrorCode::MissionInactive,
                "mission is inactive or expired",
            ));
        }
        if mission.max_actions == 0 || spec.resource_budget.max_steps == 0 {
            return Err(runtime_error(
                ErrorCode::BudgetExhausted,
                "mission action and agent step budgets must be non-zero",
            ));
        }
        if mission.allowed_capabilities.iter().any(is_capability_all)
            || spec
                .requested_authority
                .capabilities
                .iter()
                .any(is_capability_all)
        {
            return Err(runtime_error(
                ErrorCode::CapabilityAllForbidden,
                "Capability::All is forbidden for synthesized agents",
            ));
        }
        if spec
            .requested_authority
            .capabilities
            .iter()
            .any(|capability| !mission.allowed_capabilities.contains(capability))
        {
            return Err(runtime_error(
                ErrorCode::CapabilityOutsideAuthority,
                "requested authority exceeds the mission envelope",
            ));
        }
        if spec
            .requested_tools
            .iter()
            .any(|tool_id| !mission.allowed_tools.contains(tool_id))
        {
            return Err(runtime_error(
                ErrorCode::ToolOutsideMission,
                "requested tool is outside the mission allowlist",
            ));
        }

        let model_manifest_digest = model.manifest_digest(&spec.requested_model)?;
        let resolver =
            ContextResolver::for_r1(model_manifest_digest, mission.policy_epoch, context_version)?;
        let semantic_context = resolver.resolve(&spec, &registry)?;
        let semantic_context_digest = semantic_context.canonical_digest()?;

        let mut bound_tools = Vec::with_capacity(spec.requested_tools.len());
        let mut approved_tools = Vec::with_capacity(spec.requested_tools.len());
        for tool_id in &spec.requested_tools {
            let tool_digest = registry.resolve(tool_id)?.manifest_digest()?;
            bound_tools.push((tool_id.clone(), tool_digest));
            approved_tools.push(BoundTool {
                tool_id: tool_id.clone(),
                tool_manifest_digest: tool_digest,
            });
        }

        let runtime_config_digest = canonical_digest(
            "aeon-r1-runtime-config-v1",
            &(mission.max_actions, spec.resource_budget.max_steps),
        )?;
        let capability_manifest = CapabilityManifest {
            version: 1,
            model_manifest_digest: semantic_context.model_manifest_digest,
            approved_tools,
            permissions: PermissionSet {
                capabilities: spec.requested_authority.capabilities.clone(),
            },
            runtime_config_digest,
            tool_registry_root_digest: semantic_context.tool_registry_root_digest,
        };
        let capability_manifest_digest = capability_manifest.canonical_digest()?;

        let lease_id = LeaseId::new(format!("lease-{}", uuid::Uuid::new_v4()))?;
        let lease_expiry = std::cmp::min(mission.expires_at, now + Duration::minutes(5));
        let mut lease_certificate = AuthorityLeaseCertificate {
            lease_id: lease_id.clone(),
            mission_id: mission.mission_id.clone(),
            agent_id: agent_id.clone(),
            parent_agent_id: None,
            organization_version: mission.organization_version,
            policy_epoch: mission.policy_epoch,
            granted_authority: AuthoritySet {
                capabilities: spec.requested_authority.capabilities.clone(),
            },
            delegable_authority: AuthoritySet {
                capabilities: Vec::new(),
            },
            capability_manifest_digest,
            semantic_context_digest,
            issued_at: now,
            expires_at: lease_expiry,
            signature: SignatureBytes::new(Vec::new()),
        };
        let action_signing_key = SigningKey::generate(&mut OsRng);
        let lease_verifying_key = action_signing_key.verifying_key();
        let signature = action_signing_key.sign(&lease_certificate.signing_payload()?);
        lease_certificate.signature = SignatureBytes::new(signature.to_bytes().to_vec());

        let runtime_binding = RuntimeBinding {
            agent_id: agent_id.clone(),
            lifecycle: AgentLifecycle::Active,
            lease_id: lease_id.clone(),
            semantic_context_digest,
            bound_tools,
        };
        let lease_record = LeaseRecord::active(lease_id);

        let metrics = Arc::new(MetricCounters::default());
        let hypervisor = NexusHypervisor::new(HypervisorConfig::default())
            .map_err(|error| runtime_error(ErrorCode::ExecutionFailed, error.to_string()))?;
        let execution_port = NexusExecutionPort::new(hypervisor, registry.clone(), metrics.clone());

        let store = InMemoryMissionStore::new(mission.clone());
        store.append(MissionEventKind::MissionCreated);
        store.append(MissionEventKind::ContextResolved);
        store.append(MissionEventKind::LeaseIssued);
        store.append(MissionEventKind::AgentActivated);

        Ok(Self {
            mission,
            agent_id,
            spec,
            model,
            registry,
            semantic_context: RwLock::new(semantic_context),
            runtime_binding,
            lease_certificate,
            lease_record,
            lease_verifying_key,
            action_signing_key,
            protocol_gate: ProtocolGate::default(),
            action_gate: ActionGate,
            execution_port,
            metrics,
            store,
            action_certificates: Mutex::new(Vec::new()),
            steps_consumed: AtomicU64::new(0),
            actions_consumed: AtomicU64::new(0),
        })
    }

    pub async fn run_once(&self) -> Result<RunOutcome, RuntimeError> {
        reserve_budget(
            &self.steps_consumed,
            self.spec.resource_budget.max_steps,
            "agent step",
        )?;
        self.metrics.model_call();
        let semantic_context = self
            .semantic_context
            .read()
            .map_err(|_| runtime_error(ErrorCode::Internal, "semantic context lock poisoned"))?
            .clone();
        let response = self
            .model
            .generate(ModelRequest {
                agent_id: self.agent_id.clone(),
                spec: self.spec.clone(),
                semantic_context: semantic_context.clone(),
                resolved_system_instruction: resolved_system_instruction(&self.spec)?,
            })
            .await?;

        self.metrics.protocol_gate_call();
        let message = match self.protocol_gate.parse(&response.raw_output) {
            Ok(message) => {
                self.store.append(MissionEventKind::ProtocolAccepted);
                message
            }
            Err(error) => {
                self.store
                    .append(MissionEventKind::ProtocolRejected(error.code()));
                return Err(error);
            }
        };

        match message {
            AgentMessage::Final(final_result) => {
                self.store.append(MissionEventKind::FinalProduced);
                Ok(RunOutcome::Final(final_result))
            }
            AgentMessage::ToolCall(proposal) => {
                self.store.append(MissionEventKind::PlanAccepted);
                self.metrics.action_gate_call();
                let authorized = self.action_gate.authorize(
                    &self.mission,
                    &self.runtime_binding,
                    &self.lease_certificate,
                    &self.lease_record,
                    &semantic_context,
                    &self.registry,
                    &proposal.tool_id,
                    &proposal.arguments,
                    &self.lease_verifying_key,
                    &self.action_signing_key,
                    Utc::now(),
                );
                let (authorized_execution, artifact) = match authorized {
                    Ok(value) => value,
                    Err(error) => {
                        self.store
                            .append(MissionEventKind::ActionRejected(error.code()));
                        return Err(error);
                    }
                };

                if let Err(error) = reserve_budget(
                    &self.actions_consumed,
                    self.mission.max_actions,
                    "mission action",
                ) {
                    self.store
                        .append(MissionEventKind::ActionRejected(error.code()));
                    return Err(error);
                }

                self.store.append(MissionEventKind::ActionAuthorized);
                self.store.append(MissionEventKind::AuthorizationIssued);
                self.store.insert_authorization(artifact.record.clone())?;
                self.action_certificates
                    .lock()
                    .map_err(|_| {
                        runtime_error(ErrorCode::Internal, "certificate ledger lock poisoned")
                    })?
                    .push(artifact.certificate);
                self.store.consume_authorization(
                    &artifact.record.record_id,
                    artifact.record.generation,
                )?;
                self.store.append(MissionEventKind::AuthorizationConsumed);

                let output = match self
                    .execution_port
                    .execute(authorized_execution, || {
                        self.store.append(MissionEventKind::ExecutionStarted)
                    })
                    .await
                {
                    Ok(output) => output,
                    Err(error) => {
                        if error.code() == ErrorCode::ToolManifestMismatch {
                            self.store
                                .append(MissionEventKind::ExecutionRejectedBeforeNexus(
                                    ErrorCode::ToolManifestMismatch,
                                ));
                        } else {
                            self.store
                                .append(MissionEventKind::ExecutionFailed(error.code()));
                        }
                        return Err(error);
                    }
                };
                if output.success {
                    self.store.append(MissionEventKind::ExecutionCompleted);
                } else {
                    self.store.append(MissionEventKind::ExecutionFailed(
                        ErrorCode::ExecutionFailed,
                    ));
                }
                Ok(RunOutcome::Executed(Box::new(output)))
            }
        }
    }

    pub fn metrics(&self) -> R1Metrics {
        self.metrics.snapshot()
    }

    pub fn authorization_count(&self) -> usize {
        self.store.authorization_count()
    }

    /// Snapshot the immutable action certificates retained by the R1 in-memory ledger.
    pub fn authorization_certificates(&self) -> Vec<ActionCertificate> {
        self.action_certificates
            .lock()
            .map(|certificates| certificates.clone())
            .unwrap_or_default()
    }

    /// Snapshot mutable authorization consumption state separately from certificates.
    pub fn authorization_records(&self) -> Vec<AuthorizationRecord> {
        self.store.authorization_records()
    }

    pub fn event_kinds(&self) -> Vec<MissionEventKind> {
        self.store.event_kinds()
    }

    pub fn verify_event_completeness(&self) -> Result<(), RuntimeError> {
        self.store.verify_event_completeness()
    }

    pub fn semantic_context(&self) -> SemanticContext {
        self.semantic_context
            .read()
            .expect("semantic context lock poisoned")
            .clone()
    }

    pub fn replace_semantic_context(
        &self,
        semantic_context: SemanticContext,
    ) -> Result<(), RuntimeError> {
        *self
            .semantic_context
            .write()
            .map_err(|_| runtime_error(ErrorCode::Internal, "semantic context lock poisoned"))? =
            semantic_context;
        Ok(())
    }

    pub fn replace_registered_tool(&self, tool: RegisteredTool) -> Result<(), RuntimeError> {
        self.registry.replace(tool)
    }
}

fn is_capability_all(capability: &Capability) -> bool {
    capability == &Capability::All
}

fn reserve_budget(counter: &AtomicU64, limit: u64, budget_name: &str) -> Result<(), RuntimeError> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |consumed| {
            (consumed < limit).then_some(consumed + 1)
        })
        .map(|_| ())
        .map_err(|_| {
            runtime_error(
                ErrorCode::BudgetExhausted,
                format!("{budget_name} budget exhausted"),
            )
        })
}
