use risc0_zkvm::sha::{Digest, Impl, Sha256, DIGEST_BYTES};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// A hashable node within a Merkle tree.
pub trait Hashable: Clone + Copy {
    /// Returns the parent node within the tree of the two given nodes.
    fn combine(_: &Self, _: &Self) -> Self;

    /// Returns a blank leaf node.
    fn blank() -> Self;
}

impl Hashable for Digest {
    /// Returns a blank leaf node.
    fn blank() -> Self {
        Digest::default()
    }

    /// Returns the parent node within the tree of the two given nodes.
    fn combine(lhs: &Self, rhs: &Self) -> Self {
        let mut bytes = [0u8; 2 * DIGEST_BYTES];
        let mut offset: usize = 0;
        // Write the left child
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(lhs.as_ref());
        offset += DIGEST_BYTES;
        // Write the right child
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(rhs.as_ref());
        offset += DIGEST_BYTES;
        assert_eq!(offset, 2 * DIGEST_BYTES);
        // Now produce the hash
        *Impl::hash_bytes(&bytes)
    }
}

/// A path from a position in a particular commitment tree to the root of that tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePath<const COMMITMENT_TREE_DEPTH: usize> {
    #[serde(with = "BigArray")]
    auth_path: [(Digest, bool); COMMITMENT_TREE_DEPTH],
}

impl<const COMMITMENT_TREE_DEPTH: usize> MerklePath<COMMITMENT_TREE_DEPTH> {
    /// Constructs a Merkle path directly from a path and position.
    pub fn from_path(auth_path: [(Digest, bool); COMMITMENT_TREE_DEPTH]) -> Self {
        MerklePath { auth_path }
    }

    /// Returns the root of the tree corresponding to this path applied to `leaf`.
    pub fn root(&self, leaf: Digest) -> Digest {
        self.auth_path
            .iter()
            .fold(leaf, |root, (p, leaf_is_on_right)| match leaf_is_on_right {
                false => Digest::combine(&root, p),
                true => Digest::combine(p, &root),
            })
    }
}

impl<const COMMITMENT_TREE_DEPTH: usize> Default for MerklePath<COMMITMENT_TREE_DEPTH> {
    fn default() -> Self {
        MerklePath {
            auth_path: [(Digest::default(), false); COMMITMENT_TREE_DEPTH],
        }
    }
}
