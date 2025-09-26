use crate::utils::hash_two;
use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};
lazy_static! {
    pub static ref PADDING_LEAF: Digest =
        Digest::from_hex("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06")
            .unwrap();
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
    pub fn root(&self, leaf: &Digest) -> Digest {
        self.0.iter().fold(
            *leaf,
            |root, (p, leaf_is_on_right)| match leaf_is_on_right {
                false => hash_two(&root, p),
                true => hash_two(p, &root),
            },
        )
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

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
