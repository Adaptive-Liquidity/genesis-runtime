use std::collections::VecDeque;
use std::sync::Mutex;

use aeon_agent_runtime::{
    canonical_digest, AgentSpec, Digest, ErrorCode, ModelClient, ModelRef, ModelRequest,
    ModelResponse, RuntimeError, SemanticContext,
};
use async_trait::async_trait;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TestModelTraceEntry {
    pub request: TestModelRequest,
    pub response: ModelResponse,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TestModelRequest {
    pub agent_id: aeon_agent_runtime::AgentId,
    pub spec: AgentSpec,
    pub semantic_context: SemanticContext,
    pub resolved_system_instruction: String,
}

impl From<ModelRequest> for TestModelRequest {
    fn from(request: ModelRequest) -> Self {
        Self {
            agent_id: request.agent_id,
            spec: request.spec,
            semantic_context: request.semantic_context,
            resolved_system_instruction: request.resolved_system_instruction,
        }
    }
}

#[derive(Debug)]
pub struct ScriptedModelClient {
    responses: Mutex<VecDeque<String>>,
    trace: Mutex<Vec<TestModelTraceEntry>>,
}

impl ScriptedModelClient {
    pub fn new<I, S>(responses: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            responses: Mutex::new(responses.into_iter().map(Into::into).collect()),
            trace: Mutex::new(Vec::new()),
        }
    }

    pub fn trace(&self) -> Vec<TestModelTraceEntry> {
        self.trace.lock().expect("test trace lock poisoned").clone()
    }

    #[allow(dead_code)]
    pub fn remaining_responses(&self) -> usize {
        self.responses
            .lock()
            .expect("test response lock poisoned")
            .len()
    }
}

#[async_trait]
impl ModelClient for ScriptedModelClient {
    async fn generate(&self, request: ModelRequest) -> Result<ModelResponse, RuntimeError> {
        let raw_output = self
            .responses
            .lock()
            .map_err(|_| RuntimeError::new(ErrorCode::ModelFailed, "test response lock poisoned"))?
            .pop_front()
            .ok_or_else(|| RuntimeError::new(ErrorCode::ModelFailed, "scripted model exhausted"))?;
        let response = ModelResponse { raw_output };
        self.trace
            .lock()
            .map_err(|_| RuntimeError::new(ErrorCode::ModelFailed, "test trace lock poisoned"))?
            .push(TestModelTraceEntry {
                request: request.into(),
                response: response.clone(),
            });
        Ok(response)
    }

    fn manifest_digest(&self, requested_model: &ModelRef) -> Result<Digest, RuntimeError> {
        canonical_digest("aeon-scripted-model-manifest-v1", requested_model)
    }
}
