use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use chrono::{DateTime, Duration, Utc};
use nexus::{Capability, HypervisorConfig, NexusHypervisor, ToolOutput};

use crate::execution::{runtime_error, ActionGate, MetricCounters, NexusExecutionPort};
use crate::{
    canonical_digest, resolved_system_instruction, validate_context_continuation,
    ActionCertificate, AgentId, AgentMessage, AgentSpec, AuthorityEvent, AuthorityKernel,
    AuthoritySet, AuthorizationRecord, BoundTool, CapabilityManifest, ContextResolver, ErrorCode,
    FinalResult, InMemoryKeyCustody, InMemoryMissionStore, KeyCustody, KeyId, LeaseId, LeaseRecord,
    LeaseSnapshot, MissionEnvelope, MissionEventKind, ModelClient, ModelRequest, PermissionSet,
    ProtocolGate, RegisteredTool, RenewalRequest, RootLeaseRequest, RuntimeError, SemanticContext,
    ToolRegistry, ValidatedAuthority,
};

pub use crate::execution::R1Metrics;
pub type R2Runtime = R1Runtime;

#[derive(Clone, Debug)]
pub enum RunOutcome {
    Executed(Box<ToolOutput>),
    Final(FinalResult),
}

struct ModelAuthorityObservation {
    lease: LeaseSnapshot,
    validated: ValidatedAuthority,
}

pub struct R1Runtime {
    mission: MissionEnvelope,
    agent_id: AgentId,
    spec: AgentSpec,
    model: Arc<dyn ModelClient>,
    registry: ToolRegistry,
    semantic_context: Arc<RwLock<SemanticContext>>,
    authority_kernel: AuthorityKernel,
    key_custody: Arc<InMemoryKeyCustody>,
    protocol_gate: ProtocolGate,
    action_gate: ActionGate,
    execution_port: NexusExecutionPort,
    metrics: Arc<MetricCounters>,
    store: Arc<InMemoryMissionStore>,
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
        Self::bootstrap_r2(
            mission,
            agent_id,
            spec,
            model,
            registry,
            context_version,
            AuthoritySet {
                capabilities: Vec::new(),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn bootstrap_r2(
        mission: MissionEnvelope,
        agent_id: AgentId,
        spec: AgentSpec,
        model: Arc<dyn ModelClient>,
        registry: ToolRegistry,
        context_version: u64,
        delegable_authority: AuthoritySet,
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
        let mission_authority = AuthoritySet::new(mission.allowed_capabilities.clone())?;
        let requested_authority = AuthoritySet::new(spec.requested_authority.capabilities.clone())?;
        if !requested_authority.is_subset_of(&mission_authority) {
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

        let mut approved_tools = Vec::with_capacity(spec.requested_tools.len());
        for tool_id in &spec.requested_tools {
            let tool_digest = registry.resolve(tool_id)?.manifest_digest()?;
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
        let lease_expiry = std::cmp::min(mission.expires_at, now + Duration::minutes(5));
        let key_custody = Arc::new(InMemoryKeyCustody::generate(KeyId::new(format!(
            "key-{}",
            uuid::Uuid::new_v4()
        ))?)?);
        let kernel_custody: Arc<dyn KeyCustody> = key_custody.clone();
        let authority_kernel = AuthorityKernel::bootstrap(
            RootLeaseRequest {
                mission: mission.clone(),
                agent_id: agent_id.clone(),
                granted_authority: AuthoritySet {
                    capabilities: spec.requested_authority.capabilities.clone(),
                },
                delegable_authority,
                capability_manifest,
                semantic_context_digest,
                expires_at: lease_expiry,
            },
            kernel_custody.clone(),
            now,
        )?;

        let metrics = Arc::new(MetricCounters::default());
        let hypervisor_config = HypervisorConfig::default();
        NexusHypervisor::new(hypervisor_config.clone()).map_err(|_| {
            runtime_error(ErrorCode::ExecutionFailed, "Nexus initialization failed")
        })?;
        let semantic_context = Arc::new(RwLock::new(semantic_context));
        let store = Arc::new(InMemoryMissionStore::new(mission.clone()));
        let execution_port = NexusExecutionPort::new(
            hypervisor_config,
            registry.clone(),
            authority_kernel.clone(),
            semantic_context.clone(),
            store.clone(),
            kernel_custody,
            metrics.clone(),
        );

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
            semantic_context,
            authority_kernel,
            key_custody,
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
        let semantic_context = self
            .semantic_context
            .read()
            .map_err(|_| runtime_error(ErrorCode::Internal, "semantic context lock poisoned"))?
            .clone();
        let model_authority = self.observe_model_authority(&semantic_context, Utc::now())?;
        reserve_budget(
            &self.steps_consumed,
            self.spec.resource_budget.max_steps,
            "agent step",
        )?;
        let resolved_system_instruction = resolved_system_instruction(&self.spec)?;
        let attempt_id = self.store.begin_attempt();
        self.metrics.model_call();
        let response = match self
            .model
            .generate(ModelRequest {
                agent_id: self.agent_id.clone(),
                spec: self.spec.clone(),
                semantic_context: semantic_context.clone(),
                resolved_system_instruction,
            })
            .await
        {
            Ok(response) => response,
            Err(error) => {
                self.store
                    .append_for_attempt(attempt_id, MissionEventKind::ModelFailed(error.code()));
                return Err(error);
            }
        };

        self.metrics.protocol_gate_call();
        let message = match self.protocol_gate.parse(&response.raw_output) {
            Ok(message) => {
                self.store
                    .append_for_attempt(attempt_id, MissionEventKind::ProtocolAccepted);
                message
            }
            Err(error) => {
                self.store.append_for_attempt(
                    attempt_id,
                    MissionEventKind::ProtocolRejected(error.code()),
                );
                return Err(error);
            }
        };

        match message {
            AgentMessage::Final(final_result) => {
                if let Err(error) =
                    self.accept_model_final(&model_authority, attempt_id, Utc::now())
                {
                    self.store.append_for_attempt(
                        attempt_id,
                        MissionEventKind::FinalRejected(error.code()),
                    );
                    return Err(error);
                }
                Ok(RunOutcome::Final(final_result))
            }
            AgentMessage::ToolCall(proposal) => {
                self.store
                    .append_for_attempt(attempt_id, MissionEventKind::PlanAccepted);
                self.metrics.action_gate_call();
                let active_lease_id = match self.authority_kernel.root_lease_id() {
                    Ok(lease_id) => lease_id,
                    Err(error) => {
                        self.store.append_for_attempt(
                            attempt_id,
                            MissionEventKind::ActionRejected(error.code()),
                        );
                        return Err(error);
                    }
                };
                let authorized = self.action_gate.authorize(
                    &self.mission,
                    &self.agent_id,
                    &self.authority_kernel,
                    &active_lease_id,
                    &semantic_context,
                    &self.registry,
                    &proposal.tool_id,
                    &proposal.arguments,
                    self.key_custody.as_ref(),
                    Utc::now(),
                );
                let (authorized_execution, artifact) = match authorized {
                    Ok(value) => value,
                    Err(error) => {
                        self.store.append_for_attempt(
                            attempt_id,
                            MissionEventKind::ActionRejected(error.code()),
                        );
                        return Err(error);
                    }
                };

                if let Err(error) = reserve_budget(
                    &self.actions_consumed,
                    self.mission.max_actions,
                    "mission action",
                ) {
                    self.store.append_for_attempt(
                        attempt_id,
                        MissionEventKind::ActionRejected(error.code()),
                    );
                    return Err(error);
                }

                self.store
                    .append_for_attempt(attempt_id, MissionEventKind::ActionAuthorized);
                self.store
                    .append_for_attempt(attempt_id, MissionEventKind::AuthorizationIssued);
                if let Err(error) = self.store.insert_authorization(artifact.record.clone()) {
                    self.store.append_for_attempt(
                        attempt_id,
                        MissionEventKind::ExecutionRejectedBeforeNexus(error.code()),
                    );
                    return Err(error);
                }
                let certificate_result = self
                    .action_certificates
                    .lock()
                    .map_err(|_| {
                        runtime_error(ErrorCode::Internal, "certificate ledger lock poisoned")
                    })
                    .map(|mut certificates| certificates.push(artifact.certificate));
                if let Err(error) = certificate_result {
                    self.store.append_for_attempt(
                        attempt_id,
                        MissionEventKind::ExecutionRejectedBeforeNexus(error.code()),
                    );
                    return Err(error);
                }

                let output = match self
                    .execution_port
                    .execute(
                        authorized_execution,
                        || {
                            self.store.append_for_attempt(
                                attempt_id,
                                MissionEventKind::AuthorizationConsumed,
                            )
                        },
                        || {
                            self.store
                                .append_for_attempt(attempt_id, MissionEventKind::ExecutionStarted)
                        },
                    )
                    .await
                {
                    Ok(output) => output,
                    Err(error) => {
                        if error.code() != ErrorCode::ExecutionFailed {
                            self.store.append_for_attempt(
                                attempt_id,
                                MissionEventKind::ExecutionRejectedBeforeNexus(error.code()),
                            );
                        } else {
                            self.store.append_for_attempt(
                                attempt_id,
                                MissionEventKind::ExecutionFailed(error.code()),
                            );
                        }
                        return Err(error);
                    }
                };
                if output.success {
                    self.store
                        .append_for_attempt(attempt_id, MissionEventKind::ExecutionCompleted);
                } else {
                    self.store.append_for_attempt(
                        attempt_id,
                        MissionEventKind::ExecutionFailed(ErrorCode::ExecutionFailed),
                    );
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
    pub fn authorization_certificates(&self) -> Result<Vec<ActionCertificate>, RuntimeError> {
        self.action_certificates
            .lock()
            .map(|certificates| certificates.clone())
            .map_err(|_| runtime_error(ErrorCode::Internal, "certificate ledger lock poisoned"))
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

    pub fn active_lease_snapshot(&self) -> Result<LeaseSnapshot, RuntimeError> {
        let active_lease_id = self.authority_kernel.root_lease_id()?;
        self.authority_kernel.lease_snapshot(&active_lease_id)
    }

    pub fn lease_snapshot(&self, lease_id: &LeaseId) -> Result<LeaseSnapshot, RuntimeError> {
        self.authority_kernel.lease_snapshot(lease_id)
    }

    pub fn authority_events(&self) -> Result<Vec<AuthorityEvent>, RuntimeError> {
        self.authority_kernel.events()
    }

    pub fn pause(&self) -> Result<LeaseRecord, RuntimeError> {
        let active = self.active_lease_snapshot()?;
        self.authority_kernel.pause(
            &active.certificate.lease_id,
            active.record.generation,
            Utc::now(),
        )
    }

    pub fn resume(&self) -> Result<LeaseRecord, RuntimeError> {
        let active = self.active_lease_snapshot()?;
        self.authority_kernel.resume(
            &active.certificate.lease_id,
            active.record.generation,
            Utc::now(),
        )
    }

    pub fn revoke(&self, reason: impl Into<String>) -> Result<Vec<LeaseId>, RuntimeError> {
        let active = self.active_lease_snapshot()?;
        self.authority_kernel.revoke(
            &active.certificate.lease_id,
            active.record.generation,
            reason,
            Utc::now(),
        )
    }

    pub fn renew(&self, expires_at: DateTime<Utc>) -> Result<LeaseSnapshot, RuntimeError> {
        let active = self.active_lease_snapshot()?;
        let selected_tool = self.spec.requested_tools.first().ok_or_else(|| {
            runtime_error(
                ErrorCode::InvalidInput,
                "lease renewal requires at least one manifest-bound tool",
            )
        })?;
        let (_, live_manifest) = self
            .registry
            .resolve_with_capability_manifest(selected_tool, &active.manifest)?;
        let semantic_context_digest = self
            .semantic_context
            .read()
            .map_err(|_| runtime_error(ErrorCode::Internal, "semantic context lock poisoned"))?
            .canonical_digest()?;
        let renewed_id = self.authority_kernel.renew(
            RenewalRequest {
                lease_id: active.certificate.lease_id,
                expected_generation: active.record.generation,
                granted_authority: active.certificate.granted_authority,
                delegable_authority: active.certificate.delegable_authority,
                capability_manifest: live_manifest,
                semantic_context_digest,
                expires_at,
            },
            Utc::now(),
        )?;
        self.authority_kernel.lease_snapshot(&renewed_id)
    }

    pub fn refresh_expirations(&self) -> Result<Vec<LeaseId>, RuntimeError> {
        self.authority_kernel.refresh_expirations(Utc::now())
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

    fn observe_model_authority(
        &self,
        semantic_context: &SemanticContext,
        now: DateTime<Utc>,
    ) -> Result<ModelAuthorityObservation, RuntimeError> {
        if !self.mission.is_usable_at(now) {
            return Err(runtime_error(
                ErrorCode::MissionInactive,
                "mission is inactive or expired",
            ));
        }
        let active = self.active_lease_snapshot()?;
        if active.certificate.agent_id != self.agent_id
            || active.certificate.mission_id != self.mission.mission_id
            || active.certificate.organization_version != self.mission.organization_version
            || active.certificate.policy_epoch != self.mission.policy_epoch
        {
            return Err(runtime_error(
                ErrorCode::AuthorizationInvalid,
                "active authority does not match the runtime binding",
            ));
        }
        let validated = self.authority_kernel.validate_active_chain(
            &active.certificate.lease_id,
            Some(active.record.generation),
            &active.manifest,
            now,
        )?;
        validate_context_continuation(&validated.semantic_context_digest, semantic_context)?;
        Ok(ModelAuthorityObservation {
            lease: active,
            validated,
        })
    }

    fn accept_model_final(
        &self,
        observation: &ModelAuthorityObservation,
        attempt_id: u64,
        now: DateTime<Utc>,
    ) -> Result<(), RuntimeError> {
        if !self.mission.is_usable_at(now) {
            return Err(runtime_error(
                ErrorCode::MissionInactive,
                "mission became inactive or expired during model generation",
            ));
        }
        self.authority_kernel.commit_active_chain(
            &observation.lease.certificate.lease_id,
            Some(observation.lease.record.generation),
            &observation.lease.manifest,
            now,
            |validated| {
                if validated.observed_generations != observation.validated.observed_generations {
                    return Err(runtime_error(
                        ErrorCode::LeaseGenerationMismatch,
                        "authority generations changed during model generation",
                    ));
                }
                if validated.chain != observation.validated.chain
                    || validated.agent_identity_digest
                        != observation.validated.agent_identity_digest
                    || validated.capability_manifest_digest
                        != observation.validated.capability_manifest_digest
                    || validated.semantic_context_digest
                        != observation.validated.semantic_context_digest
                {
                    return Err(runtime_error(
                        ErrorCode::AuthorizationInvalid,
                        "authority binding changed during model generation",
                    ));
                }
                let current_context = self.semantic_context.read().map_err(|_| {
                    runtime_error(ErrorCode::Internal, "semantic context lock poisoned")
                })?;
                validate_context_continuation(
                    &observation.validated.semantic_context_digest,
                    &current_context,
                )?;
                self.store
                    .append_for_attempt(attempt_id, MissionEventKind::FinalProduced);
                drop(current_context);
                Ok(())
            },
        )
    }
}

fn is_capability_all(capability: &Capability) -> bool {
    capability == &Capability::All
}

#[cfg(test)]
mod tests;

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
