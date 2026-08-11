use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{ErrorCode, RuntimeError};
use crate::ids::ToolId;

/// Maximum raw model output accepted by the R1 protocol gate.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// The complete set of messages an R1 model may propose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentMessage {
    ToolCall(ToolCallProposal),
    Final(FinalResult),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCallProposal {
    pub tool_id: ToolId,
    pub arguments: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalResult {
    pub result: String,
}

#[derive(Debug, Clone)]
pub struct ProtocolGate {
    max_output_bytes: usize,
}

impl Default for ProtocolGate {
    fn default() -> Self {
        Self {
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }
}

impl ProtocolGate {
    pub fn new(max_output_bytes: usize) -> Result<Self, RuntimeError> {
        if max_output_bytes == 0 {
            return Err(protocol_error("protocol output limit must be positive"));
        }
        Ok(Self { max_output_bytes })
    }

    pub fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    pub fn parse(&self, raw: &str) -> Result<AgentMessage, RuntimeError> {
        if raw.len() > self.max_output_bytes {
            return Err(RuntimeError::new(
                ErrorCode::OutputTooLarge,
                "model output exceeds the protocol size limit",
            ));
        }

        serde_json::from_str(raw)
            .map_err(|error| protocol_error(format!("invalid closed agent protocol: {error}")))
    }
}

fn protocol_error(message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(ErrorCode::MalformedProtocol, message)
}
