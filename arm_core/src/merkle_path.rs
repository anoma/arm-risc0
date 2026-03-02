//! A Merkle path from a leaf to a root in a commitment/action tree.

use crate::{constants::EMPTY_HASH_BYTES, digest::Digest};
use serde::{Deserialize, Serialize};

/// Returns the constant padding leaf used in Merkle trees.
pub fn padding_leaf() -> Digest {
    Digest::try_from(EMPTY_HASH_BYTES.as_slice()).unwrap()
}

/// A path from a position in a particular commitment tree to the root of that tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePath(pub Vec<(Digest, bool)>);

impl MerklePath {
    /// Constructs a Merkle path directly from a path and position.
    pub fn from_path(auth_path: &[(Digest, bool)]) -> Self {
        MerklePath(auth_path.to_vec())
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
