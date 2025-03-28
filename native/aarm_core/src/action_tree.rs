use crate::merkle_path::{Hashable, MerklePath};
use risc0_zkvm::sha::Digest;

pub const ACTION_TREE_MAX_NUM: usize = 1 << ACTION_TREE_DEPTH;
pub const ACTION_TREE_DEPTH: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    leaves: Vec<Digest>,
}

impl MerkleTree {
    pub fn new(leaves: Vec<Digest>) -> Self {
        assert!(
            leaves.len() <= ACTION_TREE_MAX_NUM,
            "The number of leaves exceeds the ACTION_TREE_MAX_NUM"
        );
        MerkleTree { leaves }
    }

    pub fn insert(&mut self, value: Digest) {
        self.leaves.push(value)
    }

    pub fn root(&self) -> Digest {
        let mut cur_layer = self.leaves.clone();
        cur_layer.resize(ACTION_TREE_MAX_NUM, Digest::default());
        while cur_layer.len() > 1 {
            cur_layer = cur_layer
                .chunks(2)
                .map(|pair| Digest::combine(&pair[0], &pair[1]))
                .collect();
        }
        cur_layer[0]
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
    /// Returns an `Option` containing a `MerklePath` of depth `ACTION_TREE_DEPTH` if the leaf exists in the tree.
    /// The `MerklePath` is a vector of tuples, where each tuple contains:
    /// - A `Digest` representing the sibling node's hash.
    /// - A `bool` indicating whether the sibling is on the left (`true`) or right (`false`).
    ///
    /// Returns `None` if the leaf is not found in the tree.
    pub fn generate_path(&self, cur_leave: Digest) -> Option<MerklePath<ACTION_TREE_DEPTH>> {
        let mut cur_layer = self.leaves.clone();
        cur_layer.resize(ACTION_TREE_MAX_NUM, Digest::blank());
        if let Some(position) = cur_layer.iter().position(|&v| v == cur_leave) {
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
                        .map(|pair| Digest::combine(&pair[0], &pair[1]))
                        .collect();

                    build_merkle_path_inner(prev_layer, position / 2, path);
                }
            }
            build_merkle_path_inner(cur_layer, position, &mut merkle_path);
            Some(MerklePath::<ACTION_TREE_DEPTH>::from_path(
                match merkle_path.try_into() {
                    Ok(path) => path,
                    Err(_) => return None, // Return None if the conversion fails
                },
            ))
        } else {
            None
        }
    }
}
