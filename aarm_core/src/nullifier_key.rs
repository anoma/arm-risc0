use rand::Rng;
use risc0_zkvm::sha::{Digest, Impl, Sha256, DIGEST_BYTES};
use serde::{Deserialize, Serialize};

/// Nullifier key
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct NullifierKey(Digest);

impl NullifierKey {
    pub fn new(nf_key: Digest) -> NullifierKey {
        NullifierKey(nf_key)
    }
    /// Compute the commitment to the nullifier key
    pub fn commit(&self) -> NullifierKeyCommitment {
        let bytes: [u8; DIGEST_BYTES] = *self.0.as_ref();
        NullifierKeyCommitment(*Impl::hash_bytes(&bytes))
    }

    pub fn inner(&self) -> Digest {
        self.0
    }

    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> NullifierKey {
        NullifierKey(Digest::from_bytes(bytes))
    }

    pub fn random_pair() -> (NullifierKey, NullifierKeyCommitment) {
        let mut rng = rand::thread_rng();
        let nf_key = NullifierKey(Digest::new(rng.gen()));
        let nk_commitment = nf_key.commit();
        (nf_key, nk_commitment)
    }
}

/// Commitment to nullifier key
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct NullifierKeyCommitment(Digest);

impl NullifierKeyCommitment {
    pub fn inner(&self) -> Digest {
        self.0
    }

    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> NullifierKeyCommitment {
        NullifierKeyCommitment(Digest::from_bytes(bytes))
    }
}
