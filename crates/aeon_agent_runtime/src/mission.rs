use chrono::{DateTime, Utc};
use nexus::Capability;
use serde::{Deserialize, Serialize};

use crate::ids::{MissionId, ToolId};

/// Trusted limits supplied by the human principal for an R1 mission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissionEnvelope {
    pub mission_id: MissionId,
    pub allowed_tools: Vec<ToolId>,
    pub allowed_capabilities: Vec<Capability>,
    pub policy_epoch: u64,
    pub organization_version: u64,
    pub active: bool,
    pub expires_at: DateTime<Utc>,
    pub max_actions: u64,
}

impl MissionEnvelope {
    pub fn is_usable_at(&self, now: DateTime<Utc>) -> bool {
        self.active && self.max_actions > 0 && now < self.expires_at
    }

    pub fn allows_tool(&self, tool_id: &ToolId) -> bool {
        self.allowed_tools.iter().any(|allowed| allowed == tool_id)
    }

    pub fn allows_capability(&self, capability: &Capability) -> bool {
        self.allowed_capabilities
            .iter()
            .any(|allowed| allowed == capability)
    }

    pub fn contains_capability_all(&self) -> bool {
        self.allowed_capabilities
            .iter()
            .any(|capability| capability == &Capability::All)
    }
}
