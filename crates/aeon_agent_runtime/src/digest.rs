use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::{ErrorCode, Result, RuntimeError};

const DIGEST_BYTES: usize = 32;

/// A SHA-256 digest serialized as a lowercase hexadecimal string.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; DIGEST_BYTES]);

impl Digest {
    pub const fn new(bytes: [u8; DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let bytes = <[u8; DIGEST_BYTES]>::try_from(bytes).map_err(|_| {
            RuntimeError::new(
                ErrorCode::InvalidInput,
                format!("digest must contain exactly {DIGEST_BYTES} bytes"),
            )
        })?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        let mut encoded = String::with_capacity(DIGEST_BYTES * 2);
        for byte in self.0 {
            use std::fmt::Write as _;
            let _ = write!(encoded, "{byte:02x}");
        }
        encoded
    }

    pub fn from_hex(value: &str) -> Result<Self> {
        if value.len() != DIGEST_BYTES * 2 || !value.is_ascii() {
            return Err(RuntimeError::new(
                ErrorCode::InvalidInput,
                "digest must be 64 lowercase hexadecimal characters",
            ));
        }
        let mut bytes = [0_u8; DIGEST_BYTES];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = decode_hex(chunk[0]).ok_or_else(|| {
                RuntimeError::new(ErrorCode::InvalidInput, "digest contains non-hex data")
            })?;
            let low = decode_hex(chunk[1]).ok_or_else(|| {
                RuntimeError::new(ErrorCode::InvalidInput, "digest contains non-hex data")
            })?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

const fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Digest({self})")
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value).map_err(serde::de::Error::custom)
    }
}

/// JSON that is recursively key-sorted before serialization or hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalJson(Value);

impl CanonicalJson {
    pub fn new(value: Value) -> Self {
        Self(canonicalize_json(value))
    }

    pub fn as_value(&self) -> &Value {
        &self.0
    }

    pub fn into_value(self) -> Value {
        self.0
    }
}

impl Serialize for CanonicalJson {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CanonicalJson {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Value::deserialize(deserializer).map(Self::new)
    }
}

pub fn canonical_digest<T>(domain: &str, value: &T) -> Result<Digest>
where
    T: Serialize + ?Sized,
{
    if domain.is_empty() || domain.len() > u32::MAX as usize {
        return Err(RuntimeError::new(
            ErrorCode::InvalidInput,
            "digest domain must contain 1 to u32::MAX bytes",
        ));
    }
    let value = serde_json::to_value(value).map_err(canonical_error)?;
    let canonical = canonicalize_json(value);
    let encoded = serde_json::to_vec(&canonical).map_err(canonical_error)?;

    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u32).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(encoded);
    Ok(Digest::new(hasher.finalize().into()))
}

pub fn canonical_bytes<T>(domain: &str, value: &T) -> Result<Vec<u8>>
where
    T: Serialize + ?Sized,
{
    if domain.is_empty() {
        return Err(RuntimeError::new(
            ErrorCode::InvalidInput,
            "digest domain must contain at least one byte",
        ));
    }
    let value = serde_json::to_value(value).map_err(canonical_error)?;
    let canonical = canonicalize_json(value);
    let encoded = serde_json::to_vec(&canonical).map_err(canonical_error)?;
    let domain_length = u32::try_from(domain.len())
        .map_err(|_| RuntimeError::new(ErrorCode::InvalidInput, "digest domain is too large"))?;
    let encoded_length = u64::try_from(encoded.len()).map_err(|_| {
        RuntimeError::new(ErrorCode::InvalidInput, "canonical payload is too large")
    })?;
    let mut output = Vec::with_capacity(4 + domain.len() + 8 + encoded.len());
    output.extend_from_slice(&domain_length.to_be_bytes());
    output.extend_from_slice(domain.as_bytes());
    output.extend_from_slice(&encoded_length.to_be_bytes());
    output.extend_from_slice(&encoded);
    Ok(output)
}

pub(crate) fn canonical_value_bytes(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(&canonicalize_json(value.clone())).map_err(canonical_error)
}

fn canonical_error(error: serde_json::Error) -> RuntimeError {
    RuntimeError::new(ErrorCode::CanonicalSerialization, error.to_string())
}

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        Value::Object(values) => {
            let mut entries: Vec<_> = values.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let sorted = entries
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json(value)))
                .collect::<Map<String, Value>>();
            Value::Object(sorted)
        }
        primitive => primitive,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::canonical_bytes;
    use crate::error::ErrorCode;

    #[test]
    fn canonical_bytes_rejects_an_empty_domain() {
        let error = canonical_bytes("", &json!({})).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
    }
}
