use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[cfg(test)]
use std::sync::atomic::AtomicBool;

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
    #[cfg(test)]
    fail_authorization_consumed_append: AtomicBool,
    #[cfg(test)]
    fail_execution_started_append: AtomicBool,
    agent_record: Mutex<Option<AgentRuntimeRecord>>,
    lease: Mutex<Option<(AuthorityLeaseCertificate, LeaseRecord)>>,
    authorization_records: Mutex<Vec<AuthorizationRecord>>,
    authorization_attempts: Mutex<BTreeMap<AuthorizationId, u64>>,
}

impl InMemoryMissionStore {
    pub fn new(mission: MissionEnvelope) -> Self {
        Self {
            mission,
            events: Mutex::new(Vec::new()),
            next_attempt_id: AtomicU64::new(0),
            #[cfg(test)]
            fail_authorization_consumed_append: AtomicBool::new(false),
            #[cfg(test)]
            fail_execution_started_append: AtomicBool::new(false),
            agent_record: Mutex::new(None),
            lease: Mutex::new(None),
            authorization_records: Mutex::new(Vec::new()),
            authorization_attempts: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn mission(&self) -> MissionEnvelope {
        self.mission.clone()
    }

    pub fn append(&self, kind: MissionEventKind) -> Result<(), RuntimeError> {
        self.append_event(None, kind)
    }

    pub fn begin_attempt(&self) -> u64 {
        self.next_attempt_id.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn append_for_attempt(
        &self,
        attempt_id: u64,
        kind: MissionEventKind,
    ) -> Result<(), RuntimeError> {
        self.append_event(Some(attempt_id), kind)
    }

    fn append_event(
        &self,
        attempt_id: Option<u64>,
        kind: MissionEventKind,
    ) -> Result<(), RuntimeError> {
        #[cfg(test)]
        if matches!(kind, MissionEventKind::AuthorizationConsumed)
            && self
                .fail_authorization_consumed_append
                .swap(false, Ordering::AcqRel)
        {
            return Err(RuntimeError::new(
                ErrorCode::Internal,
                "injected AuthorizationConsumed evidence append failure",
            ));
        }
        #[cfg(test)]
        if matches!(kind, MissionEventKind::ExecutionStarted)
            && self
                .fail_execution_started_append
                .swap(false, Ordering::AcqRel)
        {
            return Err(RuntimeError::new(
                ErrorCode::Internal,
                "injected ExecutionStarted evidence append failure",
            ));
        }
        let mut events = self
            .events
            .lock()
            .map_err(|_| RuntimeError::new(ErrorCode::Internal, "mission event lock poisoned"))?;
        let sequence = events.len() as u64 + 1;
        events.push(MissionEvent {
            sequence,
            mission_id: self.mission.mission_id.clone(),
            attempt_id,
            kind,
            occurred_at: Utc::now(),
        });
        Ok(())
    }

    pub fn events(&self) -> Result<Vec<MissionEvent>, RuntimeError> {
        self.events
            .lock()
            .map(|events| events.clone())
            .map_err(|_| RuntimeError::new(ErrorCode::Internal, "mission event lock poisoned"))
    }

    pub fn set_agent_record(&self, record: AgentRuntimeRecord) -> Result<(), RuntimeError> {
        *self
            .agent_record
            .lock()
            .map_err(|_| RuntimeError::new(ErrorCode::Internal, "agent record lock poisoned"))? =
            Some(record);
        Ok(())
    }

    pub fn agent_record(&self) -> Result<Option<AgentRuntimeRecord>, RuntimeError> {
        self.agent_record
            .lock()
            .map(|record| record.clone())
            .map_err(|_| RuntimeError::new(ErrorCode::Internal, "agent record lock poisoned"))
    }

    pub fn set_lease(
        &self,
        certificate: AuthorityLeaseCertificate,
        record: LeaseRecord,
    ) -> Result<(), RuntimeError> {
        *self
            .lease
            .lock()
            .map_err(|_| RuntimeError::new(ErrorCode::Internal, "lease record lock poisoned"))? =
            Some((certificate, record));
        Ok(())
    }

    pub fn lease(&self) -> Result<Option<(AuthorityLeaseCertificate, LeaseRecord)>, RuntimeError> {
        self.lease
            .lock()
            .map(|lease| lease.clone())
            .map_err(|_| RuntimeError::new(ErrorCode::Internal, "lease record lock poisoned"))
    }

    pub fn insert_authorization(&self, record: AuthorizationRecord) -> Result<(), RuntimeError> {
        self.insert_authorization_inner(record, None)
    }

    pub(crate) fn insert_authorization_for_attempt(
        &self,
        attempt_id: u64,
        record: AuthorizationRecord,
    ) -> Result<(), RuntimeError> {
        if attempt_id == 0 {
            return Err(RuntimeError::new(
                ErrorCode::InvalidInput,
                "authorization attempt identifier must be nonzero",
            ));
        }
        self.insert_authorization_inner(record, Some(attempt_id))
    }

    fn insert_authorization_inner(
        &self,
        record: AuthorizationRecord,
        attempt_id: Option<u64>,
    ) -> Result<(), RuntimeError> {
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
        let mut attempts = attempt_id
            .map(|_| {
                self.authorization_attempts.lock().map_err(|_| {
                    RuntimeError::new(ErrorCode::Internal, "authorization attempt lock poisoned")
                })
            })
            .transpose()?;
        if let (Some(attempts), Some(attempt_id)) = (attempts.as_mut(), attempt_id) {
            attempts.insert(record.record_id.clone(), attempt_id);
        }
        records.push(record);
        Ok(())
    }

    pub fn authorization_records(&self) -> Result<Vec<AuthorizationRecord>, RuntimeError> {
        self.authorization_records
            .lock()
            .map(|records| records.clone())
            .map_err(|_| {
                RuntimeError::new(ErrorCode::Internal, "authorization store lock poisoned")
            })
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
        validate_available_record(record, expected_generation)?;
        record.remaining_budget.actions -= 1;
        record.state = crate::action::AuthorizationState::Consumed;
        record.generation += 1;
        Ok(record.clone())
    }

    pub(crate) fn consume_authorization_with<T>(
        &self,
        record_id: &AuthorizationId,
        expected_generation: u64,
        commit: impl FnOnce() -> Result<T, RuntimeError>,
    ) -> Result<T, RuntimeError> {
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
        validate_available_record(record, expected_generation)?;
        let committed = commit()?;
        record.remaining_budget.actions -= 1;
        record.state = crate::action::AuthorizationState::Consumed;
        record.generation += 1;
        Ok(committed)
    }

    pub fn event_kinds(&self) -> Result<Vec<MissionEventKind>, RuntimeError> {
        Ok(self.events()?.into_iter().map(|event| event.kind).collect())
    }

    pub fn authorization_count(&self) -> Result<usize, RuntimeError> {
        self.authorization_records
            .lock()
            .map(|records| records.len())
            .map_err(|_| {
                RuntimeError::new(ErrorCode::Internal, "authorization store lock poisoned")
            })
    }

    pub fn verify_event_completeness(&self) -> Result<(), RuntimeError> {
        let events = self.events()?;
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

        let authorization_records = self.authorization_records.lock().map_err(|_| {
            RuntimeError::new(ErrorCode::Internal, "authorization store lock poisoned")
        })?;
        let authorization_attempts = self.authorization_attempts.lock().map_err(|_| {
            RuntimeError::new(ErrorCode::Internal, "authorization attempt lock poisoned")
        })?;
        let mut consumed_by_attempt: BTreeMap<u64, usize> = BTreeMap::new();
        for record in authorization_records
            .iter()
            .filter(|record| record.state == crate::action::AuthorizationState::Consumed)
        {
            let attempt_id = authorization_attempts
                .get(&record.record_id)
                .ok_or_else(|| {
                    incomplete("consumed authorization is not bound to an execution attempt")
                })?;
            *consumed_by_attempt.entry(*attempt_id).or_default() += 1;
        }
        for (attempt_id, consumed_count) in consumed_by_attempt {
            let evidence_count = attempts
                .get(&attempt_id)
                .into_iter()
                .flatten()
                .filter(|event| matches!(event, MissionEventKind::AuthorizationConsumed))
                .count();
            if evidence_count < consumed_count {
                return Err(incomplete(
                    "consumed authorization is missing AuthorizationConsumed evidence",
                ));
            }
        }

        Ok(())
    }
}

fn validate_available_record(
    record: &AuthorizationRecord,
    expected_generation: u64,
) -> Result<(), RuntimeError> {
    if record.state != crate::action::AuthorizationState::Issued
        || record.generation != expected_generation
        || record.remaining_budget.actions == 0
    {
        return Err(RuntimeError::new(
            ErrorCode::AuthorizationInvalid,
            "authorization state, generation, or remaining budget is stale",
        ));
    }
    Ok(())
}

#[cfg(test)]
impl InMemoryMissionStore {
    pub(crate) fn fail_authorization_consumed_append_for_test(&self) {
        self.fail_authorization_consumed_append
            .store(true, Ordering::Release);
    }

    pub(crate) fn fail_execution_started_append_for_test(&self) {
        self.fail_execution_started_append
            .store(true, Ordering::Release);
    }

    pub(crate) fn poison_events_for_test(&self) {
        let _guard = self.events.lock().expect("event lock must begin healthy");
        panic!("poison mission events for deterministic failure coverage");
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
                ExecutionRejectedBeforeNexus(_),
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
