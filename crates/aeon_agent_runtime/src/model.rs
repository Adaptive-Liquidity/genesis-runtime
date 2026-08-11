use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::agent::{AgentSpec, SemanticContext};
use crate::digest::Digest;
use crate::error::RuntimeError;
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

#[async_trait]
pub trait ModelClient: Send + Sync {
    async fn generate(&self, request: ModelRequest) -> Result<ModelResponse, RuntimeError>;

    fn manifest_digest(&self, requested_model: &ModelRef) -> Result<Digest, RuntimeError>;
}
