use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use crate::action::AuthorizationRecord;
use crate::agent::AgentRuntimeRecord;
use crate::authority::{AuthorityLeaseCertificate, LeaseRecord};
use crate::error::{ErrorCode, RuntimeError};
use crate::ids::{AuthorizationId, MissionId};
use crate::mission::MissionEnvelope;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MissionEventKind {
    MissionCreated,
    ContextResolved,
    LeaseIssued,
    AgentActivated,
    ProtocolAccepted,
    ProtocolRejected(ErrorCode),
    PlanAccepted,
    ActionAuthorized,
    ActionRejected(ErrorCode),
    AuthorizationIssued,
    AuthorizationConsumed,
    ExecutionStarted,
    ExecutionRejectedBeforeNexus(ErrorCode),
    ExecutionFailed(ErrorCode),
    ExecutionCompleted,
    FinalProduced,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissionEvent {
    pub sequence: u64,
    pub mission_id: MissionId,
    pub kind: MissionEventKind,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct InMemoryMissionStore {
    mission: MissionEnvelope,
    events: Mutex<Vec<MissionEvent>>,
    authorization_count: Mutex<usize>,
    agent_record: Mutex<Option<AgentRuntimeRecord>>,
    lease: Mutex<Option<(AuthorityLeaseCertificate, LeaseRecord)>>,
    authorization_records: Mutex<Vec<AuthorizationRecord>>,
}

impl InMemoryMissionStore {
    pub fn new(mission: MissionEnvelope) -> Self {
        Self {
            mission,
            events: Mutex::new(Vec::new()),
            authorization_count: Mutex::new(0),
            agent_record: Mutex::new(None),
            lease: Mutex::new(None),
            authorization_records: Mutex::new(Vec::new()),
        }
    }

    pub fn mission(&self) -> MissionEnvelope {
        self.mission.clone()
    }

    pub fn append(&self, kind: MissionEventKind) {
        let mut events = self.events.lock().expect("mission event lock poisoned");
        let sequence = events.len() as u64 + 1;
        events.push(MissionEvent {
            sequence,
            mission_id: self.mission.mission_id.clone(),
            kind,
            occurred_at: Utc::now(),
        });
    }

    pub fn events(&self) -> Vec<MissionEvent> {
        self.events
            .lock()
            .expect("mission event lock poisoned")
            .clone()
    }

    pub fn set_agent_record(&self, record: AgentRuntimeRecord) {
        *self
            .agent_record
            .lock()
            .expect("agent record lock poisoned") = Some(record);
    }

    pub fn agent_record(&self) -> Option<AgentRuntimeRecord> {
        self.agent_record
            .lock()
            .expect("agent record lock poisoned")
            .clone()
    }

    pub fn set_lease(&self, certificate: AuthorityLeaseCertificate, record: LeaseRecord) {
        *self.lease.lock().expect("lease record lock poisoned") = Some((certificate, record));
    }

    pub fn lease(&self) -> Option<(AuthorityLeaseCertificate, LeaseRecord)> {
        self.lease
            .lock()
            .expect("lease record lock poisoned")
            .clone()
    }

    pub fn insert_authorization(&self, record: AuthorizationRecord) -> Result<(), RuntimeError> {
        let mut records = self.authorization_records.lock().map_err(|_| {
            RuntimeError::new(ErrorCode::Internal, "authorization store lock poisoned")
        })?;
        if records
            .iter()
            .any(|existing| existing.record_id == record.record_id)
        {
            return Err(RuntimeError::new(
                ErrorCode::AuthorizationInvalid,
                "authorization record already exists",
            ));
        }
        records.push(record);
        self.record_authorization();
        Ok(())
    }

    pub fn authorization_records(&self) -> Vec<AuthorizationRecord> {
        self.authorization_records
            .lock()
            .expect("authorization store lock poisoned")
            .clone()
    }

    pub fn consume_authorization(
        &self,
        record_id: &AuthorizationId,
        expected_generation: u64,
    ) -> Result<AuthorizationRecord, RuntimeError> {
        let mut records = self.authorization_records.lock().map_err(|_| {
            RuntimeError::new(ErrorCode::Internal, "authorization store lock poisoned")
        })?;
        let record = records
            .iter_mut()
            .find(|record| &record.record_id == record_id)
            .ok_or_else(|| {
                RuntimeError::new(
                    ErrorCode::AuthorizationInvalid,
                    "authorization record does not exist",
                )
            })?;
        if record.state != crate::action::AuthorizationState::Issued
            || record.generation != expected_generation
            || record.remaining_budget.actions == 0
        {
            return Err(RuntimeError::new(
                ErrorCode::AuthorizationInvalid,
                "authorization state, generation, or remaining budget is stale",
            ));
        }
        record.remaining_budget.actions -= 1;
        record.state = crate::action::AuthorizationState::Consumed;
        record.generation += 1;
        Ok(record.clone())
    }

    pub fn event_kinds(&self) -> Vec<MissionEventKind> {
        self.events().into_iter().map(|event| event.kind).collect()
    }

    pub fn record_authorization(&self) {
        let mut count = self
            .authorization_count
            .lock()
            .expect("authorization count lock poisoned");
        *count += 1;
    }

    pub fn authorization_count(&self) -> usize {
        *self
            .authorization_count
            .lock()
            .expect("authorization count lock poisoned")
    }

    pub fn verify_event_completeness(&self) -> Result<(), RuntimeError> {
        let events = self.event_kinds();
        let foundational = [
            MissionEventKind::MissionCreated,
            MissionEventKind::ContextResolved,
            MissionEventKind::LeaseIssued,
            MissionEventKind::AgentActivated,
        ];
        if events.len() < foundational.len() || events[..foundational.len()] != foundational {
            return Err(incomplete(
                "mission history is missing its trusted activation prefix",
            ));
        }

        let raw_events = self.events();
        if raw_events
            .iter()
            .enumerate()
            .any(|(index, event)| event.sequence != index as u64 + 1)
        {
            return Err(incomplete("mission event sequence is not contiguous"));
        }

        for (index, event) in events.iter().enumerate() {
            if matches!(event, MissionEventKind::ExecutionCompleted)
                && !has_ordered_prefix(
                    &events[..index],
                    &[EventTag::AuthorizationConsumed, EventTag::ExecutionStarted],
                )
            {
                return Err(incomplete(
                    "execution completed without authorization consumption and start",
                ));
            }
            if matches!(event, MissionEventKind::AuthorizationConsumed)
                && !events[..index]
                    .iter()
                    .any(|kind| matches!(kind, MissionEventKind::AuthorizationIssued))
            {
                return Err(incomplete("authorization consumed without being issued"));
            }
        }

        if events
            .iter()
            .any(|event| matches!(event, MissionEventKind::ProtocolRejected(_)))
            && events.iter().any(|event| {
                matches!(
                    event,
                    MissionEventKind::ActionAuthorized
                        | MissionEventKind::AuthorizationIssued
                        | MissionEventKind::AuthorizationConsumed
                        | MissionEventKind::ExecutionStarted
                        | MissionEventKind::ExecutionCompleted
                )
            })
        {
            return Err(incomplete(
                "protocol rejection was followed by an execution transition",
            ));
        }

        for (index, event) in events.iter().enumerate() {
            if matches!(event, MissionEventKind::ActionRejected(_))
                && events[index + 1..].iter().any(is_execution_transition)
            {
                return Err(incomplete(
                    "action rejection was followed by an authorization or execution transition",
                ));
            }
            if matches!(event, MissionEventKind::ExecutionRejectedBeforeNexus(_))
                && events[index + 1..].iter().any(|kind| {
                    matches!(
                        kind,
                        MissionEventKind::ExecutionStarted | MissionEventKind::ExecutionCompleted
                    )
                })
            {
                return Err(incomplete(
                    "pre-Nexus execution rejection was followed by execution",
                ));
            }
        }

        for (index, event) in events.iter().enumerate() {
            if matches!(event, MissionEventKind::ExecutionStarted)
                && !events[index + 1..].iter().any(|kind| {
                    matches!(
                        kind,
                        MissionEventKind::ExecutionCompleted | MissionEventKind::ExecutionFailed(_)
                    )
                })
            {
                return Err(incomplete("execution start has no terminal outcome event"));
            }
        }

        Ok(())
    }
}

fn is_execution_transition(event: &MissionEventKind) -> bool {
    matches!(
        event,
        MissionEventKind::ActionAuthorized
            | MissionEventKind::AuthorizationIssued
            | MissionEventKind::AuthorizationConsumed
            | MissionEventKind::ExecutionStarted
            | MissionEventKind::ExecutionFailed(_)
            | MissionEventKind::ExecutionCompleted
    )
}

#[derive(Clone, Copy)]
enum EventTag {
    AuthorizationConsumed,
    ExecutionStarted,
}

fn has_ordered_prefix(events: &[MissionEventKind], required: &[EventTag]) -> bool {
    let mut next = 0;
    for event in events {
        let matches = match required.get(next) {
            Some(EventTag::AuthorizationConsumed) => {
                matches!(event, MissionEventKind::AuthorizationConsumed)
            }
            Some(EventTag::ExecutionStarted) => matches!(event, MissionEventKind::ExecutionStarted),
            None => return true,
        };
        if matches {
            next += 1;
        }
    }
    next == required.len()
}

fn incomplete(message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(ErrorCode::EventIncomplete, message)
}
