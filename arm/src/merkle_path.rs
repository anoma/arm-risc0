//! A Merkle path from a leaf to a root in a commitment/action tree.

#[cfg(feature = "zkvm")]
use crate::utils::hash_two;
use crate::Digest;
use serde::{Deserialize, Serialize};

/// The constant padding leaf used in Merkle trees.
/// This is the hash of an empty string (same value as INITIAL_ROOT in compliance.rs).
/// Hex: cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06
const PADDING_LEAF_WORDS: [u32; 8] = [
    0x832f1dcc, 0x7adb4584, 0xf91d43ec, 0x1f878aee,
    0x5eaae740, 0x56c04f06, 0xc6f83e63, 0x067bab0f,
];

/// Returns the padding leaf value.
#[cfg(not(feature = "zkvm"))]
pub fn padding_leaf() -> Digest {
    Digest(PADDING_LEAF_WORDS)
}

/// Returns the padding leaf value.
#[cfg(feature = "zkvm")]
pub fn padding_leaf() -> Digest {
    Digest::new(PADDING_LEAF_WORDS)
}

/// A path from a position in a particular commitment tree to the root of that tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePath(pub Vec<(Digest, bool)>);

impl MerklePath {
    /// Constructs a Merkle path directly from a path and position.
    pub fn from_path(auth_path: &[(Digest, bool)]) -> Self {
        MerklePath(auth_path.to_vec())
    }

    /// Returns the root of the tree corresponding to this path applied to `leaf`.
    #[cfg(feature = "zkvm")]
    pub fn root(&self, leaf: &Digest) -> Digest {
        self.0.iter().fold(
            *leaf,
            |root, (p, leaf_is_on_right)| match leaf_is_on_right {
                false => hash_two(&root, p),
                true => hash_two(p, &root),
            },
        )
    }

    /// Returns the length of the Merkle path.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Checks if the Merkle path is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Creates an empty Merkle path.
    pub fn empty() -> Self {
        MerklePath(vec![])
    }
}

impl Default for MerklePath {
    fn default() -> Self {
        MerklePath(vec![
            (Digest::default(), false);
           10 // COMMITMENT_TREE_DEPTH, only for testing
        ])
    }
}
