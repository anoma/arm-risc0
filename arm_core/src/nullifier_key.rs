//! Nullifier key and its commitment

use crate::error::ArmError;
use risc0_zkp::core::digest::{Digest, DIGEST_BYTES};
use risc0_zkp::core::hash::sha::{Impl, Sha256};
use serde::{Deserialize, Serialize};

/// Nullifier key
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NullifierKey([u8; DIGEST_BYTES]);

impl NullifierKey {
    /// Create a new nullifier key from bytes
    pub fn new(nf_key: [u8; DIGEST_BYTES]) -> NullifierKey {
        NullifierKey::from_bytes(nf_key)
    }

    /// Compute the commitment to the nullifier key
    pub fn commit(&self) -> NullifierKeyCommitment {
        NullifierKeyCommitment(*Impl::hash_bytes(self.inner()))
    }

    /// Get the inner bytes of the nullifier key
    pub fn inner(&self) -> &[u8] {
        &self.0
    }

    /// Create a nullifier key from bytes
    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> NullifierKey {
        NullifierKey(bytes)
    }
}

impl Default for NullifierKey {
    fn default() -> Self {
        NullifierKey([0u8; DIGEST_BYTES])
    }
}

/// Commitment to nullifier key
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct NullifierKeyCommitment(Digest);

impl NullifierKeyCommitment {
    /// Get the inner nullifier key commitment
    pub fn inner(&self) -> Digest {
        self.0
    }

    /// Create a nullifier key commitment from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<NullifierKeyCommitment, ArmError> {
        let nk_cm: Digest =
            Digest::try_from(bytes).map_err(|_| ArmError::InvalidNullifierCommitment)?;
        Ok(NullifierKeyCommitment(nk_cm))
    }

    /// Get the bytes of the nullifier key commitment
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Default for NullifierKeyCommitment {
    fn default() -> Self {
        NullifierKey::default().commit()
    }
}
