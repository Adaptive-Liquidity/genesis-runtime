use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::agent::{AgentSpec, SemanticContext};
use crate::digest::{canonical_digest, Digest};
use crate::error::{ErrorCode, RuntimeError};
use crate::ids::{AgentId, ModelRef};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRequest {
    pub agent_id: AgentId,
    pub spec: AgentSpec,
    pub semantic_context: SemanticContext,
    pub resolved_system_instruction: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelResponse {
    pub raw_output: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelTraceEntry {
    pub request: ModelRequest,
    pub response: ModelResponse,
}

#[async_trait]
pub trait ModelClient: Send + Sync {
    async fn generate(&self, request: ModelRequest) -> Result<ModelResponse, RuntimeError>;

    fn manifest_digest(&self, requested_model: &ModelRef) -> Result<Digest, RuntimeError>;
}

/// Deterministic R1 model adapter that records only model-facing data.
#[derive(Debug)]
pub struct ScriptedModelClient {
    responses: Mutex<VecDeque<String>>,
    trace: Mutex<Vec<ModelTraceEntry>>,
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

    pub fn trace(&self) -> Vec<ModelTraceEntry> {
        self.trace
            .lock()
            .expect("model trace lock poisoned")
            .clone()
    }

    pub fn remaining_responses(&self) -> usize {
        self.responses
            .lock()
            .expect("scripted model response lock poisoned")
            .len()
    }
}

#[async_trait]
impl ModelClient for ScriptedModelClient {
    async fn generate(&self, request: ModelRequest) -> Result<ModelResponse, RuntimeError> {
        let raw_output = self
            .responses
            .lock()
            .expect("scripted model response lock poisoned")
            .pop_front()
            .ok_or_else(|| RuntimeError::new(ErrorCode::ModelFailed, "scripted model exhausted"))?;
        let response = ModelResponse { raw_output };
        self.trace
            .lock()
            .expect("model trace lock poisoned")
            .push(ModelTraceEntry {
                request,
                response: response.clone(),
            });
        Ok(response)
    }

    fn manifest_digest(&self, requested_model: &ModelRef) -> Result<Digest, RuntimeError> {
        canonical_digest("aeon-scripted-model-manifest-v1", requested_model)
    }
}
