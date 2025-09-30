use crate::error::ArmError;
use rand::Rng;
use risc0_zkvm::sha::{Digest, Impl, Sha256, DIGEST_BYTES};
use serde::{Deserialize, Serialize};

/// Nullifier key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NullifierKey(Vec<u8>);

impl NullifierKey {
    pub fn new(nf_key: &[u8]) -> NullifierKey {
        NullifierKey(nf_key.to_vec())
    }
    /// Compute the commitment to the nullifier key
    pub fn commit(&self) -> NullifierKeyCommitment {
        NullifierKeyCommitment(*Impl::hash_bytes(self.inner()))
    }

    pub fn inner(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> NullifierKey {
        NullifierKey(bytes.to_vec())
    }

    pub fn random_pair() -> (NullifierKey, NullifierKeyCommitment) {
        let mut rng = rand::thread_rng();
        let rng_bytes: [u8; DIGEST_BYTES] = rng.gen();
        let nf_key = NullifierKey(rng_bytes.to_vec());
        let nk_commitment = nf_key.commit();
        (nf_key, nk_commitment)
    }
}

impl Default for NullifierKey {
    fn default() -> Self {
        NullifierKey(vec![0u8; DIGEST_BYTES])
    }
}

/// Commitment to nullifier key
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct NullifierKeyCommitment(Digest);

impl NullifierKeyCommitment {
    pub fn inner(&self) -> Digest {
        self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<NullifierKeyCommitment, ArmError> {
        let nk_cm: Digest =
            Digest::try_from(bytes).map_err(|_| ArmError::InvalidNullifierCommitment)?;
        Ok(NullifierKeyCommitment(nk_cm))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Default for NullifierKeyCommitment {
    fn default() -> Self {
        NullifierKey::default().commit()
    }
}
