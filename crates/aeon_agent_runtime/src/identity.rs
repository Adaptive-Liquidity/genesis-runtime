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

        let AgentIdentityCertificate {
            agent_id,
            key_id,
            verifying_key_bytes,
            issuer_agent_id,
            issuer_key_id,
            issued_at,
            signature: _,
        } = self;

        canonical_bytes(
            "aeon-agent-identity-certificate-v1",
            &SigningPayload {
                agent_id,
                key_id,
                verifying_key_bytes,
                issuer_agent_id,
                issuer_key_id,
                issued_at,
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

    /// Verifies that this certificate is bound to the supplied issuer certificate.
    ///
    /// This checks identifiers, public keys, and the signature only. It does not
    /// establish that the issuer is trusted or that its certificate is valid.
    pub fn verify_issued_by(&self, issuer: &Self) -> Result<()> {
        if self.issuer_agent_id.as_ref() != Some(&issuer.agent_id)
            || self.issuer_key_id != issuer.key_id
        {
            return Err(RuntimeError::new(
                ErrorCode::IdentityInvalid,
                "identity certificate issuer binding is invalid",
            ));
        }
        self.verify_signature(&issuer.verifying_key()?)
    }

    /// Verifies the certificate's self-signature and self-issuer binding.
    ///
    /// A valid self-signature is not a trust decision. Callers must separately
    /// decide whether this identity is an accepted trust anchor.
    pub fn verify_self_signed(&self) -> Result<()> {
        if self.issuer_agent_id.is_some() || self.issuer_key_id != self.key_id {
            return Err(RuntimeError::new(
                ErrorCode::IdentityInvalid,
                "self-signed identity certificate issuer binding is invalid",
            ));
        }
        self.verify_signature(&self.verifying_key()?)
    }

    pub(crate) fn verify_signature(&self, issuer_verifying_key: &VerifyingKey) -> Result<()> {
        self.verifying_key()?;
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
