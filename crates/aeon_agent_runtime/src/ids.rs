use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{ErrorCode, Result, RuntimeError};

const MAX_IDENTIFIER_BYTES: usize = 128;

fn validate_identifier(kind: &'static str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(RuntimeError::new(
            ErrorCode::InvalidIdentifier,
            format!("{kind} must contain 1 to {MAX_IDENTIFIER_BYTES} bytes"),
        ));
    }

    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(RuntimeError::new(
            ErrorCode::InvalidIdentifier,
            format!("{kind} must not be empty"),
        ));
    };
    if !first.is_ascii_alphanumeric() {
        return Err(RuntimeError::new(
            ErrorCode::InvalidIdentifier,
            format!("{kind} must start with an ASCII letter or digit"),
        ));
    }
    if !chars.all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':' | '/' | '@')
    }) {
        return Err(RuntimeError::new(
            ErrorCode::InvalidIdentifier,
            format!("{kind} contains unsupported characters"),
        ));
    }
    Ok(())
}

macro_rules! string_id {
    ($name:ident, $kind:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl AsRef<str>) -> Result<Self> {
                let value = value.as_ref();
                validate_identifier($kind, value)?;
                Ok(Self(value.to_owned()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl TryFrom<String> for $name {
            type Error = RuntimeError;

            fn try_from(value: String) -> Result<Self> {
                Self::new(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

string_id!(MissionId, "mission id");
string_id!(AgentId, "agent id");
string_id!(LeaseId, "lease id");
string_id!(AuthorizationId, "authorization id");
string_id!(CertificateId, "certificate id");
string_id!(ToolId, "tool id");
string_id!(ModelRef, "model reference");
string_id!(MemoryRef, "memory reference");
string_id!(RetrievalIndexRef, "retrieval index reference");
string_id!(InstructionProfileRef, "instruction profile reference");
