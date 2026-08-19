//! Host-engine operations on [`Resource`]: randomized construction and the
//! k256 kind/quantity mappings. The `Resource` type itself, its
//! commitment/nullifier/nonce derivations, and the witness/public types live
//! in `anoma-rm-core` and are re-exported here unchanged.

pub use arm_core::resource::*;

use crate::error::ArmError;
use crate::nullifier_key::NullifierKeyCommitment;
use k256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use k256::{ProjectivePoint, Scalar, Secp256k1};
use rand::rngs::OsRng;
use rand::Rng;
use risc0_zkvm::sha::rust_crypto::Sha256 as Sha256Type;
use risc0_zkvm::Digest;

/// DST constant for hashing to curve in RFC 9380.
const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";
const DIGEST_BYTES: usize = 32;

/// Computes the kind point for the given `logic_ref` and `label_ref` without
/// requiring a full [`Resource`] to be constructed.
pub(crate) fn generate_resource_kind(
    logic_ref: Digest,
    label_ref: Digest,
) -> Result<ProjectivePoint, ArmError> {
    let mut bytes = [0u8; DIGEST_BYTES * 2];
    bytes[0..DIGEST_BYTES].clone_from_slice(logic_ref.as_ref());
    bytes[DIGEST_BYTES..DIGEST_BYTES * 2].clone_from_slice(label_ref.as_ref());
    Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256Type>>(&[&bytes], &[DST])
        .map_err(|_| ArmError::InvalidResourceKind)
}

/// Create a new resource with a freshly drawn randomness seed.
#[allow(clippy::too_many_arguments)]
pub fn create(
    logic_ref: Digest,
    label_ref: Digest,
    quantity: u128,
    value_ref: Digest,
    is_ephemeral: bool,
    nonce: Digest,
    nk_commitment: NullifierKeyCommitment,
) -> Resource {
    Resource {
        logic_ref,
        label_ref,
        quantity,
        value_ref,
        is_ephemeral,
        nonce: nonce.into(),
        nk_commitment,
        rand_seed: OsRng.gen(),
    }
}

/// Reset the randomness seed of the resource.
pub fn reset_randomness(resource: &mut Resource) {
    resource.rand_seed = OsRng.gen();
}

/// Convert the resource quantity to a field element.
pub fn quantity_scalar(resource: &Resource) -> Scalar {
    Scalar::from(resource.quantity)
}

/// Compute the kind of the resource.
pub fn kind(resource: &Resource) -> Result<ProjectivePoint, ArmError> {
    generate_resource_kind(resource.logic_ref, resource.label_ref)
}
