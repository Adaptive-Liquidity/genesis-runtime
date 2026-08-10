use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable, machine-readable failure categories exposed by the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidIdentifier,
    InvalidInput,
    CanonicalSerialization,
    MalformedProtocol,
    OutputTooLarge,
    UnknownTool,
    DuplicateTool,
    ToolOutsideMission,
    CapabilityOutsideAuthority,
    CapabilityAllForbidden,
    ToolManifestMismatch,
    SemanticContextChanged,
    ContextResolutionFailed,
    MissionInactive,
    AgentInactive,
    LeaseInactive,
    AuthorizationInvalid,
    BudgetExhausted,
    ExecutionFailed,
    ModelFailed,
    EventIncomplete,
    Internal,
}

/// A claim-safe runtime error with a stable code and a human-readable detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeError {
    code: ErrorCode,
    message: String,
}

impl RuntimeError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {}",
            error_code_name(self.code),
            self.message
        )
    }
}

impl std::error::Error for RuntimeError {}

const fn error_code_name(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::InvalidIdentifier => "invalid identifier",
        ErrorCode::InvalidInput => "invalid input",
        ErrorCode::CanonicalSerialization => "canonical serialization failed",
        ErrorCode::MalformedProtocol => "malformed protocol",
        ErrorCode::OutputTooLarge => "output too large",
        ErrorCode::UnknownTool => "unknown tool",
        ErrorCode::DuplicateTool => "duplicate tool",
        ErrorCode::ToolOutsideMission => "tool outside mission",
        ErrorCode::CapabilityOutsideAuthority => "capability outside authority",
        ErrorCode::CapabilityAllForbidden => "Capability::All forbidden",
        ErrorCode::ToolManifestMismatch => "tool manifest mismatch",
        ErrorCode::SemanticContextChanged => "semantic context changed",
        ErrorCode::ContextResolutionFailed => "context resolution failed",
        ErrorCode::MissionInactive => "mission inactive",
        ErrorCode::AgentInactive => "agent inactive",
        ErrorCode::LeaseInactive => "lease inactive",
        ErrorCode::AuthorizationInvalid => "authorization invalid",
        ErrorCode::BudgetExhausted => "budget exhausted",
        ErrorCode::ExecutionFailed => "execution failed",
        ErrorCode::ModelFailed => "model failed",
        ErrorCode::EventIncomplete => "event incomplete",
        ErrorCode::Internal => "internal error",
    }
}

pub type Result<T> = std::result::Result<T, RuntimeError>;
