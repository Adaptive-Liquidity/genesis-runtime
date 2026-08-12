use std::collections::BTreeMap;
use std::fmt;

use serde::de::{DeserializeOwned, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::digest::{canonical_digest, Digest};
use crate::error::{ErrorCode, RuntimeError};
use crate::ids::ToolId;

/// Maximum raw model output accepted by the R1 protocol gate.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// The complete set of messages an R1 model may propose.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentMessage {
    ToolCall(ToolCallProposal),
    Final(FinalResult),
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProtocolFieldShape {
    ToolId,
    Object,
    String,
}

impl ProtocolFieldShape {
    fn accepts(self, value: &Value) -> bool {
        match self {
            Self::ToolId | Self::String => value.is_string(),
            Self::Object => value.is_object(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
struct ProtocolFieldSchema {
    name: &'static str,
    shape: ProtocolFieldShape,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct ProtocolVariantSchema {
    name: &'static str,
    fields: &'static [ProtocolFieldSchema],
}

impl ProtocolVariantSchema {
    fn field(self, name: &str) -> Option<&'static ProtocolFieldSchema> {
        self.fields.iter().find(|field| field.name == name)
    }
}

#[derive(Debug, Serialize)]
struct ProtocolSchema {
    tag: &'static str,
    variants: &'static [ProtocolVariantSchema],
}

const TOOL_CALL_FIELDS: &[ProtocolFieldSchema] = &[
    ProtocolFieldSchema {
        name: "tool_id",
        shape: ProtocolFieldShape::ToolId,
    },
    ProtocolFieldSchema {
        name: "arguments",
        shape: ProtocolFieldShape::Object,
    },
];
const FINAL_FIELDS: &[ProtocolFieldSchema] = &[ProtocolFieldSchema {
    name: "result",
    shape: ProtocolFieldShape::String,
}];
const TOOL_CALL_SCHEMA: ProtocolVariantSchema = ProtocolVariantSchema {
    name: "tool_call",
    fields: TOOL_CALL_FIELDS,
};
const FINAL_SCHEMA: ProtocolVariantSchema = ProtocolVariantSchema {
    name: "final",
    fields: FINAL_FIELDS,
};
const PROTOCOL_VARIANTS: &[ProtocolVariantSchema] = &[TOOL_CALL_SCHEMA, FINAL_SCHEMA];
const PROTOCOL_SCHEMA: ProtocolSchema = ProtocolSchema {
    tag: "kind",
    variants: PROTOCOL_VARIANTS,
};

impl AgentMessage {
    /// Digest of the complete closed wire schema accepted by [`ProtocolGate`].
    pub fn schema_digest() -> Result<Digest, RuntimeError> {
        canonical_digest("aeon-agent-protocol-schema-v1", &PROTOCOL_SCHEMA)
    }
}

impl Serialize for AgentMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::ToolCall(ToolCallProposal { tool_id, arguments }) => {
                let tool_id: &ToolId = tool_id;
                let arguments: &Value = arguments;
                if !TOOL_CALL_FIELDS[1].shape.accepts(arguments) {
                    return Err(serde::ser::Error::custom(format!(
                        "{} must have {:?} shape",
                        TOOL_CALL_FIELDS[1].name, TOOL_CALL_FIELDS[1].shape
                    )));
                }
                let mut map = serializer.serialize_map(Some(TOOL_CALL_SCHEMA.fields.len() + 1))?;
                map.serialize_entry(PROTOCOL_SCHEMA.tag, TOOL_CALL_SCHEMA.name)?;
                map.serialize_entry(TOOL_CALL_FIELDS[0].name, tool_id)?;
                map.serialize_entry(TOOL_CALL_FIELDS[1].name, arguments)?;
                map.end()
            }
            Self::Final(FinalResult { result }) => {
                let result: &String = result;
                let mut map = serializer.serialize_map(Some(FINAL_SCHEMA.fields.len() + 1))?;
                map.serialize_entry(PROTOCOL_SCHEMA.tag, FINAL_SCHEMA.name)?;
                map.serialize_entry(FINAL_FIELDS[0].name, result)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for AgentMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AgentMessageVisitor;

        impl<'de> Visitor<'de> for AgentMessageVisitor {
            type Value = AgentMessage;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a closed AEON agent protocol message")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some((name, value)) = map.next_entry::<String, Value>()? {
                    if values.insert(name.clone(), value).is_some() {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate protocol field: {name}"
                        )));
                    }
                }

                let kind = take_field::<String>(
                    &mut values,
                    ProtocolFieldSchema {
                        name: PROTOCOL_SCHEMA.tag,
                        shape: ProtocolFieldShape::String,
                    },
                )
                .map_err(serde::de::Error::custom)?;
                let schema = PROTOCOL_SCHEMA
                    .variants
                    .iter()
                    .copied()
                    .find(|variant| variant.name == kind)
                    .ok_or_else(|| {
                        serde::de::Error::custom(format!(
                            "unknown protocol variant in {}: {kind}",
                            PROTOCOL_SCHEMA.tag
                        ))
                    })?;

                if let Some(unknown) = values.keys().find(|name| schema.field(name).is_none()) {
                    return Err(serde::de::Error::custom(format!(
                        "unknown field for {}: {unknown}",
                        schema.name
                    )));
                }

                let message = if schema.name == TOOL_CALL_SCHEMA.name {
                    let tool_id: ToolId = take_field(&mut values, TOOL_CALL_FIELDS[0])
                        .map_err(serde::de::Error::custom)?;
                    let arguments: Value = take_field(&mut values, TOOL_CALL_FIELDS[1])
                        .map_err(serde::de::Error::custom)?;
                    AgentMessage::ToolCall(ToolCallProposal { tool_id, arguments })
                } else if schema.name == FINAL_SCHEMA.name {
                    let result: String = take_field(&mut values, FINAL_FIELDS[0])
                        .map_err(serde::de::Error::custom)?;
                    AgentMessage::Final(FinalResult { result })
                } else {
                    return Err(serde::de::Error::custom(
                        "protocol schema contains an unsupported variant",
                    ));
                };

                debug_assert!(values.is_empty());
                Ok(message)
            }
        }

        deserializer.deserialize_map(AgentMessageVisitor)
    }
}

fn take_field<T>(
    values: &mut BTreeMap<String, Value>,
    schema: ProtocolFieldSchema,
) -> Result<T, String>
where
    T: DeserializeOwned,
{
    let value = values
        .remove(schema.name)
        .ok_or_else(|| format!("missing protocol field: {}", schema.name))?;
    if !schema.shape.accepts(&value) {
        return Err(format!(
            "protocol field {} must have {:?} shape",
            schema.name, schema.shape
        ));
    }
    serde_json::from_value(value)
        .map_err(|error| format!("invalid protocol field {}: {error}", schema.name))
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

// The wire descriptor drives serialization and deserialization above. This additional
// exhaustive match keeps enum variants and payload fields compile-time coupled to those paths.
#[allow(dead_code)]
fn assert_agent_protocol_schema_coverage(message: &AgentMessage) {
    match message {
        AgentMessage::ToolCall(ToolCallProposal { tool_id, arguments }) => {
            let _ = (tool_id, arguments);
        }
        AgentMessage::Final(FinalResult { result }) => {
            let _ = result;
        }
    }
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
