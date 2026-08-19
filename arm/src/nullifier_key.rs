//! Host-engine operations on [`NullifierKey`]: random generation. The key
//! and commitment types themselves live in `anoma-rm-core` and are
//! re-exported here unchanged.

pub use arm_core::nullifier_key::*;

use rand::rngs::OsRng;
use rand::Rng;

/// Generate a random nullifier key and its commitment.
pub fn random_pair() -> (NullifierKey, NullifierKeyCommitment) {
    let rng_bytes: [u8; 32] = OsRng.gen();
    let nf_key = NullifierKey::from_bytes(rng_bytes);
    let nk_commitment = nf_key.commit();
    (nf_key, nk_commitment)
}
