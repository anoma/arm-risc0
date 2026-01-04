//! Merkle tree implementation for the action tree.

use crate::{
    error::ArmError,
    merkle_path::{MerklePath, PADDING_LEAF},
    utils::hash_two,
};
use risc0_zkvm::sha::Digest;

/// A Merkle tree structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    /// The leaves of the Merkle tree.
    pub leaves: Vec<Digest>,
}

impl MerkleTree {
    /// Creates a new Merkle tree from the given leaves.
    pub fn new(leaves: Vec<Digest>) -> Self {
        MerkleTree { leaves }
    }

    /// Inserts a new leaf into the Merkle tree.
    pub fn insert(&mut self, value: Digest) {
        self.leaves.push(value)
    }

    /// Computes the root of the Merkle tree.
    pub fn root(&self) -> Result<Digest, ArmError> {
        if self.is_empty() {
            return Err(ArmError::EmptyTree);
        }

        let len = self
            .leaves
            .len()
            .checked_next_power_of_two()
            .ok_or(ArmError::TreeTooLarge)?;
        let mut cur_layer = self.leaves.clone();
        cur_layer.resize(len, *PADDING_LEAF);
        while cur_layer.len() > 1 {
            cur_layer = cur_layer
                .chunks(2)
                .map(|pair| hash_two(&pair[0], &pair[1]))
                .collect();
        }
        Ok(cur_layer[0])
    }

    // Generate the merkle path for the current leave
    /// Generates the Merkle path for a given leaf in the Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `cur_leave` - The leaf value for which the Merkle path is to be generated.
    ///
    /// # Returns
    ///
    /// Returns an `Option` containing a `MerklePath` if the leaf exists in the tree.
    /// The `MerklePath` is a vector of tuples, where each tuple contains:
    /// - A `Digest` representing the sibling node's hash.
    /// - A `bool` indicating whether the sibling is on the left (`true`) or right (`false`).
    ///
    /// Returns `ArmError::InvalidLeaf` if the leaf is not found in the tree.
    pub fn generate_path(&self, cur_leave: &Digest) -> Result<MerklePath, ArmError> {
        if self.is_empty() {
            return Err(ArmError::EmptyTree);
        }

        if *cur_leave == *PADDING_LEAF {
            return Err(ArmError::InvalidLeaf);
        }

        let len = self
            .leaves
            .len()
            .checked_next_power_of_two()
            .ok_or(ArmError::TreeTooLarge)?;
        let mut cur_layer = self.leaves.clone();
        cur_layer.resize(len, *PADDING_LEAF);
        if let Some(position) = cur_layer.iter().position(|v| v == cur_leave) {
            let mut merkle_path = Vec::new();
            fn build_merkle_path_inner(
                cur_layer: Vec<Digest>,
                position: usize,
                path: &mut Vec<(Digest, bool)>,
            ) {
                if cur_layer.len() > 1 {
                    let sibling = {
                        let is_sibling_left = position % 2 != 0;
                        let sibling_value = if is_sibling_left {
                            cur_layer[position - 1]
                        } else {
                            cur_layer[position + 1]
                        };
                        (sibling_value, is_sibling_left)
                    };
                    path.push(sibling);

                    let prev_layer = cur_layer
                        .chunks(2)
                        .map(|pair| hash_two(&pair[0], &pair[1]))
                        .collect();

                    build_merkle_path_inner(prev_layer, position / 2, path);
                }
            }
            build_merkle_path_inner(cur_layer, position, &mut merkle_path);
            Ok(MerklePath::from_path(merkle_path.as_slice()))
        } else {
            Err(ArmError::InvalidLeaf)
        }
    }

    /// Checks if the Merkle tree is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

impl From<Vec<Digest>> for MerkleTree {
    fn from(leaves: Vec<Digest>) -> Self {
        MerkleTree::new(leaves)
    }
}
