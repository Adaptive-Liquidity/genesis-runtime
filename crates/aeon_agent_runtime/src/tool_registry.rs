use nexus::{Capability, ToolDefinition};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as ShaDigest, Sha256};
use std::sync::{Arc, RwLock};

use crate::action::EffectClass;
use crate::authority::{BoundTool, CapabilityManifest};
use crate::digest::{canonical_digest, Digest};
use crate::error::{ErrorCode, RuntimeError};
use crate::ids::ToolId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolManifest {
    pub version: u64,
    pub tool_id: ToolId,
    pub wasm_sha256: String,
    pub entry_point: String,
    pub input_schema_digest: Digest,
    pub required_capabilities: Vec<Capability>,
    pub effect_class: EffectClass,
    pub output_schema_digest: Option<Digest>,
}

impl ToolManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: u64,
        tool_id: ToolId,
        wasm_bytes: &[u8],
        entry_point: impl Into<String>,
        input_schema: Value,
        required_capabilities: Vec<Capability>,
        effect_class: EffectClass,
        output_schema: Option<Value>,
    ) -> Result<Self, RuntimeError> {
        let entry_point = entry_point.into();
        if version == 0 || wasm_bytes.is_empty() || entry_point.trim().is_empty() {
            return Err(registry_error(
                ErrorCode::InvalidInput,
                "tool manifest version, WASM, and entry point must be present",
            ));
        }
        validate_schema_definition(&input_schema)?;
        if let Some(schema) = output_schema.as_ref() {
            validate_schema_definition(schema)?;
        }

        let mut required_capabilities = required_capabilities;
        sort_capabilities(&mut required_capabilities)?;
        Ok(Self {
            version,
            tool_id,
            wasm_sha256: hex_sha256(wasm_bytes),
            entry_point,
            input_schema_digest: canonical_digest("aeon-tool-input-schema-v1", &input_schema)?,
            required_capabilities,
            effect_class,
            output_schema_digest: output_schema
                .as_ref()
                .map(|schema| canonical_digest("aeon-tool-output-schema-v1", schema))
                .transpose()?,
        })
    }

    pub fn canonical_digest(&self) -> Result<Digest, RuntimeError> {
        let mut canonical = self.clone();
        sort_capabilities(&mut canonical.required_capabilities)?;
        canonical_digest("aeon-tool-manifest-v1", &canonical)
    }
}

#[derive(Debug, Clone)]
pub struct RegisteredTool {
    manifest: ToolManifest,
    wasm_bytes: Vec<u8>,
    input_schema: Value,
    output_schema: Option<Value>,
}

impl RegisteredTool {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tool_id: ToolId,
        wasm_bytes: Vec<u8>,
        entry_point: impl Into<String>,
        input_schema: Value,
        required_capabilities: Vec<Capability>,
        effect_class: EffectClass,
        output_schema: Option<Value>,
    ) -> Result<Self, RuntimeError> {
        let entry_point = entry_point.into();
        let manifest = ToolManifest::new(
            1,
            tool_id,
            &wasm_bytes,
            entry_point,
            input_schema.clone(),
            required_capabilities,
            effect_class,
            output_schema.clone(),
        )?;
        Ok(Self {
            manifest,
            wasm_bytes,
            input_schema,
            output_schema,
        })
    }

    pub fn manifest(&self) -> &ToolManifest {
        &self.manifest
    }

    pub fn manifest_digest(&self) -> Result<Digest, RuntimeError> {
        self.manifest.canonical_digest()
    }

    pub fn input_schema(&self) -> &Value {
        &self.input_schema
    }

    pub fn output_schema(&self) -> Option<&Value> {
        self.output_schema.as_ref()
    }

    pub fn validate_input(&self, input: &Value) -> Result<(), RuntimeError> {
        validate_instance(&self.input_schema, input, "$")
    }

    pub fn tool_definition(&self) -> ToolDefinition {
        let mut definition = ToolDefinition::new(
            self.manifest.tool_id.as_str().to_owned(),
            self.wasm_bytes.clone(),
        )
        .with_entry(&self.manifest.entry_point)
        .with_capabilities(self.manifest.required_capabilities.clone());
        definition.input_schema = self.input_schema.clone();
        definition
    }
}

#[derive(Debug, Clone, Default)]
pub struct ToolRegistry {
    tools: Arc<RwLock<Vec<RegisteredTool>>>,
}

/// A coherent view of requested tools and registry identity captured under one read lock.
#[derive(Debug, Clone)]
pub(crate) struct RegistrySnapshot {
    resolved_tools: Vec<RegisteredTool>,
    bound_tools: Vec<BoundTool>,
    root_digest: Digest,
}

impl RegistrySnapshot {
    pub(crate) fn bound_tools(&self) -> &[BoundTool] {
        &self.bound_tools
    }

    pub(crate) fn root_digest(&self) -> Digest {
        self.root_digest
    }
}

impl ToolRegistry {
    pub fn from_tools(tools: Vec<RegisteredTool>) -> Result<Self, RuntimeError> {
        for (index, tool) in tools.iter().enumerate() {
            if tools[..index]
                .iter()
                .any(|existing| existing.manifest.tool_id == tool.manifest.tool_id)
            {
                return Err(registry_error(
                    ErrorCode::DuplicateTool,
                    "duplicate tool id in trusted registry",
                ));
            }
        }
        Ok(Self {
            tools: Arc::new(RwLock::new(tools)),
        })
    }

    pub fn resolve(&self, tool_id: &ToolId) -> Result<RegisteredTool, RuntimeError> {
        self.tools
            .read()
            .map_err(|_| registry_error(ErrorCode::Internal, "tool registry lock poisoned"))?
            .iter()
            .find(|tool| &tool.manifest.tool_id == tool_id)
            .cloned()
            .ok_or_else(|| registry_error(ErrorCode::UnknownTool, "tool is not registered"))
    }

    pub fn resolve_all(&self, tool_ids: &[ToolId]) -> Result<Vec<RegisteredTool>, RuntimeError> {
        Ok(self.snapshot(tool_ids)?.resolved_tools)
    }

    #[cfg(test)]
    pub(crate) fn replace(&self, replacement: RegisteredTool) -> Result<(), RuntimeError> {
        let mut tools = self
            .tools
            .write()
            .map_err(|_| registry_error(ErrorCode::Internal, "tool registry lock poisoned"))?;
        let position = tools
            .iter()
            .position(|tool| tool.manifest.tool_id == replacement.manifest.tool_id)
            .ok_or_else(|| registry_error(ErrorCode::UnknownTool, "tool is not registered"))?;
        tools[position] = replacement;
        Ok(())
    }

    pub fn root_digest(&self) -> Result<Digest, RuntimeError> {
        let tools = self
            .tools
            .read()
            .map_err(|_| registry_error(ErrorCode::Internal, "tool registry lock poisoned"))?;
        root_digest_for_tools(&tools)
    }

    pub(crate) fn snapshot(&self, tool_ids: &[ToolId]) -> Result<RegistrySnapshot, RuntimeError> {
        let tools = self
            .tools
            .read()
            .map_err(|_| registry_error(ErrorCode::Internal, "tool registry lock poisoned"))?;
        snapshot_for_tools(&tools, tool_ids)
    }

    /// Refreshes every tool binding and the registry root under one read lock.
    pub(crate) fn refresh_capability_manifest(
        &self,
        template: &CapabilityManifest,
    ) -> Result<CapabilityManifest, RuntimeError> {
        let tools = self
            .tools
            .read()
            .map_err(|_| registry_error(ErrorCode::Internal, "tool registry lock poisoned"))?;
        refresh_capability_manifest_for_tools(&tools, template)
    }

    /// Resolves the selected tool and the complete live capability manifest
    /// under one registry read lock, closing cross-tool manifest races.
    pub fn resolve_with_capability_manifest(
        &self,
        tool_id: &ToolId,
        template: &CapabilityManifest,
    ) -> Result<(RegisteredTool, CapabilityManifest), RuntimeError> {
        let tools = self
            .tools
            .read()
            .map_err(|_| registry_error(ErrorCode::Internal, "tool registry lock poisoned"))?;
        let selected = tools
            .iter()
            .find(|tool| &tool.manifest.tool_id == tool_id)
            .cloned()
            .ok_or_else(|| registry_error(ErrorCode::UnknownTool, "tool is not registered"))?;
        let manifest = refresh_capability_manifest_for_tools(&tools, template)?;
        Ok((selected, manifest))
    }
}

fn snapshot_for_tools(
    tools: &[RegisteredTool],
    tool_ids: &[ToolId],
) -> Result<RegistrySnapshot, RuntimeError> {
    let resolved_tools = tool_ids
        .iter()
        .map(|tool_id| {
            tools
                .iter()
                .find(|tool| &tool.manifest.tool_id == tool_id)
                .cloned()
                .ok_or_else(|| registry_error(ErrorCode::UnknownTool, "tool is not registered"))
        })
        .collect::<Result<Vec<_>, RuntimeError>>()?;
    let bound_tools = resolved_tools
        .iter()
        .map(|tool| {
            Ok(BoundTool {
                tool_id: tool.manifest.tool_id.clone(),
                tool_manifest_digest: tool.manifest_digest()?,
            })
        })
        .collect::<Result<Vec<_>, RuntimeError>>()?;
    Ok(RegistrySnapshot {
        resolved_tools,
        bound_tools,
        root_digest: root_digest_for_tools(tools)?,
    })
}

fn refresh_capability_manifest_for_tools(
    tools: &[RegisteredTool],
    template: &CapabilityManifest,
) -> Result<CapabilityManifest, RuntimeError> {
    let tool_ids = template
        .approved_tools
        .iter()
        .map(|bound| bound.tool_id.clone())
        .collect::<Vec<_>>();
    let snapshot = snapshot_for_tools(tools, &tool_ids).map_err(|error| {
        if error.code() == ErrorCode::UnknownTool {
            registry_error(
                ErrorCode::UnknownTool,
                "manifest-bound tool is not registered",
            )
        } else {
            error
        }
    })?;
    let mut manifest = template.clone();
    manifest.approved_tools = snapshot.bound_tools;
    manifest.tool_registry_root_digest = snapshot.root_digest;
    Ok(manifest)
}

fn root_digest_for_tools(tools: &[RegisteredTool]) -> Result<Digest, RuntimeError> {
    let mut entries = tools
        .iter()
        .map(|tool| {
            Ok(json!({
                "tool_id": tool.manifest.tool_id,
                "manifest_digest": tool.manifest_digest()?,
            }))
        })
        .collect::<Result<Vec<_>, RuntimeError>>()?;
    entries.sort_by_key(|entry| entry.to_string());
    canonical_digest("aeon-tool-registry-root-v1", &entries)
}

fn validate_schema_definition(schema: &Value) -> Result<(), RuntimeError> {
    let schema = schema.as_object().ok_or_else(|| {
        registry_error(ErrorCode::InvalidInput, "tool schema must be a JSON object")
    })?;
    const SUPPORTED_KEYWORDS: [&str; 4] =
        ["type", "required", "properties", "additionalProperties"];
    if let Some(keyword) = schema
        .keys()
        .find(|keyword| !SUPPORTED_KEYWORDS.contains(&keyword.as_str()))
    {
        return Err(registry_error(
            ErrorCode::InvalidInput,
            format!("unsupported schema keyword: {keyword}"),
        ));
    }
    if let Some(schema_type) = schema.get("type") {
        let supported_type = schema_type.as_str().is_some_and(|value| {
            matches!(
                value,
                "object" | "array" | "string" | "number" | "integer" | "boolean" | "null"
            )
        });
        if !supported_type {
            return Err(registry_error(
                ErrorCode::InvalidInput,
                "schema type must name a supported primitive type",
            ));
        }
    }
    if (schema.contains_key("required") || schema.contains_key("properties"))
        && schema.get("type").and_then(Value::as_str) != Some("object")
    {
        return Err(registry_error(
            ErrorCode::InvalidInput,
            "schema required and properties are only supported for type object",
        ));
    }
    if let Some(required) = schema.get("required") {
        let required = required.as_array().ok_or_else(|| {
            registry_error(ErrorCode::InvalidInput, "schema required must be an array")
        })?;
        if required.iter().any(|name| !name.is_string()) {
            return Err(registry_error(
                ErrorCode::InvalidInput,
                "schema required entries must be strings",
            ));
        }
    }
    if let Some(properties) = schema.get("properties") {
        let properties = properties.as_object().ok_or_else(|| {
            registry_error(
                ErrorCode::InvalidInput,
                "schema properties must be an object",
            )
        })?;
        for property_schema in properties.values() {
            validate_schema_definition(property_schema)?;
        }
    }
    if schema
        .get("additionalProperties")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(registry_error(
            ErrorCode::InvalidInput,
            "schema additionalProperties must be a boolean",
        ));
    }
    Ok(())
}

fn validate_instance(schema: &Value, value: &Value, path: &str) -> Result<(), RuntimeError> {
    if let Some(expected_type) = schema.get("type").and_then(Value::as_str) {
        let matches = match expected_type {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "number" => value.is_number(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => false,
        };
        if !matches {
            return Err(registry_error(
                ErrorCode::InvalidInput,
                format!("{path} does not match schema type {expected_type}"),
            ));
        }
    }

    if let (Some(object), Some(schema_object)) = (value.as_object(), schema.as_object()) {
        if let Some(required) = schema_object.get("required").and_then(Value::as_array) {
            for name in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(name) {
                    return Err(registry_error(
                        ErrorCode::InvalidInput,
                        format!("{path}.{name} is required"),
                    ));
                }
            }
        }

        let properties = schema_object.get("properties").and_then(Value::as_object);
        if schema_object.get("additionalProperties") == Some(&Value::Bool(false)) {
            for name in object.keys() {
                if !properties.is_some_and(|known| known.contains_key(name)) {
                    return Err(registry_error(
                        ErrorCode::InvalidInput,
                        format!("{path}.{name} is not allowed"),
                    ));
                }
            }
        }
        if let Some(properties) = properties {
            for (name, property_schema) in properties {
                if let Some(property) = object.get(name) {
                    validate_instance(property_schema, property, &format!("{path}.{name}"))?;
                }
            }
        }
    }

    Ok(())
}

fn sort_capabilities(capabilities: &mut Vec<Capability>) -> Result<(), RuntimeError> {
    let mut serialized = capabilities
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            registry_error(
                ErrorCode::InvalidInput,
                format!("capability serialization failed: {error}"),
            )
        })?;
    serialized.sort();
    let mut sorted = serialized
        .into_iter()
        .map(|item| serde_json::from_str(&item))
        .collect::<Result<Vec<Capability>, _>>()
        .map_err(|error| {
            registry_error(
                ErrorCode::InvalidInput,
                format!("capability deserialization failed: {error}"),
            )
        })?;
    sorted.dedup();
    *capabilities = sorted;
    Ok(())
}

fn hex_sha256(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn registry_error(code: ErrorCode, message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(id: &str, wasm: u8) -> RegisteredTool {
        RegisteredTool::new(
            ToolId::new(id).expect("valid tool id"),
            vec![wasm],
            "_start",
            json!({
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "additionalProperties": false
            }),
            vec![],
            EffectClass::ReadOnly,
            None,
        )
        .expect("valid tool")
    }

    #[test]
    fn registry_snapshot_keeps_tools_bindings_and_root_from_one_generation() {
        let original = tool("fixture.echo", 1);
        let replacement = tool("fixture.echo", 2);
        let registry = ToolRegistry::from_tools(vec![original.clone()]).expect("valid registry");

        let snapshot = registry
            .snapshot(&[original.manifest().tool_id.clone()])
            .expect("snapshot resolves");
        registry.replace(replacement).expect("replacement succeeds");

        assert_eq!(snapshot.resolved_tools[0].manifest(), original.manifest());
        assert_eq!(
            snapshot.bound_tools()[0].tool_manifest_digest,
            original.manifest_digest().expect("digest")
        );
        assert_eq!(
            snapshot.root_digest(),
            root_digest_for_tools(&[original]).expect("root digest")
        );
        assert_ne!(
            snapshot.root_digest(),
            registry.root_digest().expect("live root")
        );
    }

    #[test]
    fn capability_manifest_refresh_supports_no_bound_tools() {
        let registry =
            ToolRegistry::from_tools(vec![tool("fixture.echo", 1)]).expect("valid registry");
        let template = CapabilityManifest {
            version: 1,
            model_manifest_digest: Digest::new([1; 32]),
            approved_tools: vec![],
            permissions: crate::authority::PermissionSet {
                capabilities: vec![],
            },
            runtime_config_digest: Digest::new([2; 32]),
            tool_registry_root_digest: Digest::new([0; 32]),
        };

        let refreshed = registry
            .refresh_capability_manifest(&template)
            .expect("empty manifest refreshes");

        assert!(refreshed.approved_tools.is_empty());
        assert_eq!(
            refreshed.tool_registry_root_digest,
            registry.root_digest().expect("root digest")
        );
    }

    #[test]
    fn schema_required_and_properties_require_explicit_object_type() {
        for schema in [
            json!({"required": ["value"]}),
            json!({"type": "string", "required": ["value"]}),
            json!({"properties": {"value": {"type": "string"}}}),
            json!({"type": "array", "properties": {}}),
        ] {
            assert!(validate_schema_definition(&schema).is_err(), "{schema}");
        }

        assert!(validate_schema_definition(&json!({
            "type": "object",
            "required": ["value"],
            "properties": {"value": {"type": "string"}}
        }))
        .is_ok());
    }
}
