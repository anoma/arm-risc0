//! A Merkle path from a leaf to a root in a commitment/action tree.

pub use arm_core::merkle_path::{padding_leaf, MerklePath};

use crate::{
    utils::{core_to_risc0_digest, hash_two, risc0_to_core_digest},
    Digest,
};

/// Extension methods for Merkle paths that require risc0 hashing.
pub trait MerklePathExt {
    /// Returns the root of the tree corresponding to this path applied to `leaf`.
    fn root(&self, leaf: &Digest) -> Digest;
}

impl MerklePathExt for MerklePath {
    fn root(&self, leaf: &Digest) -> Digest {
        let leaf_r0 = core_to_risc0_digest(leaf);
        let result = self.0.iter().fold(leaf_r0, |root, (p, leaf_is_on_right)| {
            let p_r0 = core_to_risc0_digest(p);
            match leaf_is_on_right {
                false => hash_two(&root, &p_r0),
                true => hash_two(&p_r0, &root),
            }
        });
        risc0_to_core_digest(result)
    }
}
