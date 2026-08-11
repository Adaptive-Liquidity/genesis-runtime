use std::fmt;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::authority::SignatureBytes;
use crate::digest::{canonical_bytes, canonical_digest, Digest};
use crate::error::{ErrorCode, Result, RuntimeError};
use crate::ids::{AgentId, KeyId};

/// Custody boundary for identity signing keys.
///
/// Implementations expose only public-key and signing operations. Private key
/// material cannot be serialized or retrieved through this interface.
pub trait KeyCustody: Send + Sync {
    fn key_id(&self) -> KeyId;

    fn verifying_key(&self) -> VerifyingKey;

    fn sign(&self, payload: &[u8]) -> Result<SignatureBytes>;
}

/// Process-local key custody for tests and the R2 in-memory runtime.
///
/// This type intentionally has no serialization implementation and its debug
/// output never includes private key bytes.
pub struct InMemoryKeyCustody {
    key_id: KeyId,
    signing_key: SigningKey,
}

impl InMemoryKeyCustody {
    pub fn generate(key_id: KeyId) -> Result<Self> {
        Ok(Self {
            key_id,
            signing_key: SigningKey::generate(&mut OsRng),
        })
    }
}

impl fmt::Debug for InMemoryKeyCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryKeyCustody")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl KeyCustody for InMemoryKeyCustody {
    fn key_id(&self) -> KeyId {
        self.key_id.clone()
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    fn sign(&self, payload: &[u8]) -> Result<SignatureBytes> {
        Ok(SignatureBytes::new(
            self.signing_key.sign(payload).to_bytes().to_vec(),
        ))
    }
}

/// Immutable, issuer-signed binding between an agent and its public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIdentityCertificate {
    pub agent_id: AgentId,
    pub key_id: KeyId,
    pub verifying_key_bytes: [u8; 32],
    pub issuer_agent_id: Option<AgentId>,
    pub issuer_key_id: KeyId,
    pub issued_at: DateTime<Utc>,
    pub signature: SignatureBytes,
}

impl AgentIdentityCertificate {
    pub fn unsigned(
        agent_id: AgentId,
        key_id: KeyId,
        verifying_key: VerifyingKey,
        issuer_agent_id: Option<AgentId>,
        issuer_key_id: KeyId,
        issued_at: DateTime<Utc>,
    ) -> Self {
        Self {
            agent_id,
            key_id,
            verifying_key_bytes: verifying_key.to_bytes(),
            issuer_agent_id,
            issuer_key_id,
            issued_at,
            signature: SignatureBytes::new(Vec::new()),
        }
    }

    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct SigningPayload<'a> {
            agent_id: &'a AgentId,
            key_id: &'a KeyId,
            verifying_key_bytes: &'a [u8; 32],
            issuer_agent_id: &'a Option<AgentId>,
            issuer_key_id: &'a KeyId,
            issued_at: &'a DateTime<Utc>,
        }

        canonical_bytes(
            "aeon-agent-identity-certificate-v1",
            &SigningPayload {
                agent_id: &self.agent_id,
                key_id: &self.key_id,
                verifying_key_bytes: &self.verifying_key_bytes,
                issuer_agent_id: &self.issuer_agent_id,
                issuer_key_id: &self.issuer_key_id,
                issued_at: &self.issued_at,
            },
        )
    }

    pub fn canonical_digest(&self) -> Result<Digest> {
        canonical_digest("aeon-agent-identity-certificate-v1", self)
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.verifying_key_bytes).map_err(|_| {
            RuntimeError::new(
                ErrorCode::IdentityInvalid,
                "identity certificate contains an invalid Ed25519 public key",
            )
        })
    }

    pub fn verify_signature(&self, issuer_verifying_key: &VerifyingKey) -> Result<()> {
        self.verifying_key()?;
        if self.issuer_agent_id.is_none() && self.issuer_key_id != self.key_id {
            return Err(RuntimeError::new(
                ErrorCode::IdentityInvalid,
                "a self-signed root identity must use its own key as issuer",
            ));
        }
        let signature_bytes = <[u8; 64]>::try_from(self.signature.as_bytes()).map_err(|_| {
            RuntimeError::new(
                ErrorCode::IdentityInvalid,
                "identity certificate signature must contain exactly 64 bytes",
            )
        })?;
        let payload = self.signing_payload()?;
        let signature = Signature::from_bytes(&signature_bytes);
        issuer_verifying_key
            .verify(&payload, &signature)
            .map_err(|_| {
                RuntimeError::new(
                    ErrorCode::IdentityInvalid,
                    "identity certificate signature verification failed",
                )
            })
    }
}
