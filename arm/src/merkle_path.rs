//! A Merkle path from a leaf to a root in a commitment/action tree.

#[cfg(feature = "zkvm")]
use crate::utils::hash_two;
use crate::constants::EMPTY_HASH_WORDS;
use crate::Digest;
use serde::{Deserialize, Serialize};

/// Returns the padding leaf value (hash of an empty string).
#[cfg(not(feature = "zkvm"))]
pub fn padding_leaf() -> Digest {
    Digest(EMPTY_HASH_WORDS)
}

/// Returns the padding leaf value (hash of an empty string).
#[cfg(feature = "zkvm")]
pub fn padding_leaf() -> Digest {
    Digest::new(EMPTY_HASH_WORDS)
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
