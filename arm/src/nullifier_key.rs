//! Nullifier key helpers requiring risc0 hashing and randomness.

pub use arm_core::nullifier_key::{NullifierKey, NullifierKeyCommitment};

use arm_core::digest::DIGEST_BYTES;
use rand::{rngs::OsRng, Rng};

/// Extension methods for nullifier keys that require risc0/rand.
pub trait NullifierKeyExt {
    /// Compute the commitment to the nullifier key.
    fn commit(&self) -> NullifierKeyCommitment;

    /// Generate a random nullifier key and its commitment.
    fn random_pair() -> (NullifierKey, NullifierKeyCommitment)
    where
        Self: Sized;
}

impl NullifierKeyExt for NullifierKey {
    fn commit(&self) -> NullifierKeyCommitment {
        use risc0_zkvm::sha::{Impl, Sha256};

        let digest_r0 = *Impl::hash_bytes(self.inner());
        NullifierKeyCommitment::from_bytes(digest_r0.as_bytes()).unwrap()
    }

    fn random_pair() -> (NullifierKey, NullifierKeyCommitment) {
        let rng_bytes: [u8; DIGEST_BYTES] = OsRng.gen();
        let nf_key = NullifierKey::from_bytes(rng_bytes);
        let nk_commitment = nf_key.commit();
        (nf_key, nk_commitment)
    }
}
