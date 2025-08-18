use crate::utils::hash_two;
use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::sha::{Digest, DIGEST_WORDS};
#[cfg(feature = "nif")]
use rustler::NifStruct;
use serde::{Deserialize, Serialize};
lazy_static! {
    pub static ref PADDING_LEAF: Digest =
        Digest::from_hex("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06")
            .unwrap();
}
pub const COMMITMENT_TREE_DEPTH: usize = 32;

/// A path from a position in a particular commitment tree to the root of that tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Anoma.Arm.MerklePath")]
pub struct MerklePath<const TREE_DEPTH: usize> {
    auth_path: Vec<(Vec<u32>, bool)>,
}

impl<const TREE_DEPTH: usize> MerklePath<TREE_DEPTH> {
    /// Constructs a Merkle path directly from a path and position.
    pub fn from_path(auth_path: [(Vec<u32>, bool); TREE_DEPTH]) -> Self {
        MerklePath {
            auth_path: auth_path.to_vec(),
        }
    }
    /// Returns the root of the tree corresponding to this path applied to `leaf`.
    pub fn root(&self, leaf: &Digest) -> Vec<u32> {
        if self.auth_path.len() != TREE_DEPTH {
            panic!("Merkle path length does not match TREE_DEPTH");
        }
        self.auth_path
            .iter()
            .fold(
                leaf.as_words().to_vec(),
                |root, (p, leaf_is_on_right)| match leaf_is_on_right {
                    false => hash_two(&root, p),
                    true => hash_two(p, &root),
                },
            )
    }
}

impl<const TREE_DEPTH: usize> Default for MerklePath<TREE_DEPTH> {
    fn default() -> Self {
        MerklePath {
            auth_path: vec![(vec![0u32; DIGEST_WORDS], false); TREE_DEPTH],
        }
    }
}
