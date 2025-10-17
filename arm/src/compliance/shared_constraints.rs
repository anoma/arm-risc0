/// Constraints used in all compliance circuits.
use risc0_zkvm::Digest;

use crate::{
    error::ArmError, merkle_path::MerklePath, nullifier_key::NullifierKey, resource::Resource,
};
pub(super) fn commit(resource: &Resource) -> Digest {
    resource.commitment()
}
pub(super) fn compute_commitment_tree_root(
    resource_commitment: &Digest,
    merkle_path: &MerklePath,
    resource_is_ephemeral: bool,
    ephemeral_root: &Digest,
) -> Digest {
    if resource_is_ephemeral {
        *ephemeral_root
    } else {
        merkle_path.root(resource_commitment)
    }
}

/// By returning the logic vk of the resource we force it is loaded from memory onto the computational trace.
pub(super) fn read_resource_logic(resource: &Resource) -> Digest {
    resource.logic_ref
}

pub(super) fn compute_nullifier(
    resource: &Resource,
    commitment: &Digest,
    nf_key: &NullifierKey,
) -> Result<Digest, ArmError> {
    resource.nullifier_from_commitment(nf_key, commitment)
}
