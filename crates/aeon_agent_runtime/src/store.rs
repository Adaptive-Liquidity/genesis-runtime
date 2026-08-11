use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
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
    ModelFailed(ErrorCode),
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
    FinalRejected(ErrorCode),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissionEvent {
    pub sequence: u64,
    pub mission_id: MissionId,
    pub attempt_id: Option<u64>,
    pub kind: MissionEventKind,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct InMemoryMissionStore {
    mission: MissionEnvelope,
    events: Mutex<Vec<MissionEvent>>,
    next_attempt_id: AtomicU64,
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
            next_attempt_id: AtomicU64::new(0),
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
        self.append_event(None, kind);
    }

    pub fn begin_attempt(&self) -> u64 {
        self.next_attempt_id.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn append_for_attempt(&self, attempt_id: u64, kind: MissionEventKind) {
        self.append_event(Some(attempt_id), kind);
    }

    fn append_event(&self, attempt_id: Option<u64>, kind: MissionEventKind) {
        let mut events = self.events.lock().expect("mission event lock poisoned");
        let sequence = events.len() as u64 + 1;
        events.push(MissionEvent {
            sequence,
            mission_id: self.mission.mission_id.clone(),
            attempt_id,
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
        let events = self.events();
        let foundational = [
            MissionEventKind::MissionCreated,
            MissionEventKind::ContextResolved,
            MissionEventKind::LeaseIssued,
            MissionEventKind::AgentActivated,
        ];
        if events.len() < foundational.len()
            || events[..foundational.len()]
                .iter()
                .map(|event| &event.kind)
                .ne(foundational.iter())
            || events[..foundational.len()]
                .iter()
                .any(|event| event.attempt_id.is_some())
        {
            return Err(incomplete(
                "mission history is missing its trusted activation prefix",
            ));
        }

        if events
            .iter()
            .enumerate()
            .any(|(index, event)| event.sequence != index as u64 + 1)
        {
            return Err(incomplete("mission event sequence is not contiguous"));
        }
        if events
            .iter()
            .any(|event| event.mission_id != self.mission.mission_id)
        {
            return Err(incomplete("mission event is bound to the wrong mission"));
        }

        let mut attempts: BTreeMap<u64, Vec<MissionEventKind>> = BTreeMap::new();
        for event in &events[foundational.len()..] {
            let attempt_id = event.attempt_id.ok_or_else(|| {
                incomplete("runtime event is missing its originating attempt identifier")
            })?;
            if attempt_id == 0 {
                return Err(incomplete(
                    "runtime event has an invalid attempt identifier",
                ));
            }
            attempts
                .entry(attempt_id)
                .or_default()
                .push(event.kind.clone());
        }
        for attempt in attempts.values() {
            validate_attempt(attempt)?;
        }

        Ok(())
    }
}

fn validate_attempt(events: &[MissionEventKind]) -> Result<(), RuntimeError> {
    use MissionEventKind::*;

    let complete = matches!(
        events,
        [ModelFailed(_)]
            | [ProtocolRejected(_)]
            | [ProtocolAccepted, FinalProduced | FinalRejected(_)]
            | [ProtocolAccepted, PlanAccepted, ActionRejected(_)]
            | [
                ProtocolAccepted,
                PlanAccepted,
                ActionAuthorized,
                AuthorizationIssued,
                ExecutionRejectedBeforeNexus(_) | ExecutionFailed(_),
            ]
            | [
                ProtocolAccepted,
                PlanAccepted,
                ActionAuthorized,
                AuthorizationIssued,
                AuthorizationConsumed,
                ExecutionStarted,
                ExecutionCompleted | ExecutionFailed(_),
            ]
    );
    if complete {
        Ok(())
    } else {
        Err(incomplete(
            "attempt history is incomplete, out of order, or crosses a terminal event",
        ))
    }
}

fn incomplete(message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(ErrorCode::EventIncomplete, message)
}
