//! Action tree implementation.

use crate::{
    error::ArmError,
    merkle_path::{MerklePath, PADDING_LEAF},
    utils::hash_two,
};
use risc0_zkvm::sha::Digest;

/// The action tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionTree {
    /// The leaves of the action tree.
    pub leaves: Vec<Digest>,
}

impl ActionTree {
    /// Creates a new action tree from the given leaves.
    pub fn new(leaves: Vec<Digest>) -> Self {
        ActionTree { leaves }
    }

    /// Inserts a new leaf into the action tree.
    pub fn insert(&mut self, value: Digest) {
        self.leaves.push(value)
    }

    /// Computes the root of the action tree.
    pub fn root(&self) -> Result<Digest, ArmError> {
        let mut cur_layer = self.padded_leaves()?;
        while cur_layer.len() > 1 {
            cur_layer = cur_layer
                .chunks(2)
                .map(|pair| hash_two(&pair[0], &pair[1]))
                .collect();
        }
        Ok(cur_layer[0])
    }

    /// Generates the Merkle path for a given leaf in the action tree.
    ///
    /// Returns `ArmError::InvalidLeaf` if the leaf is not found in the tree.
    pub fn generate_path(&self, cur_leaf: &Digest) -> Result<MerklePath, ArmError> {
        if *cur_leaf == *PADDING_LEAF {
            return Err(ArmError::InvalidLeaf);
        }

        let mut cur_layer = self.padded_leaves()?;
        let mut position = cur_layer
            .iter()
            .position(|v| v == cur_leaf)
            .ok_or(ArmError::InvalidLeaf)?;
        let mut merkle_path = Vec::new();

        while cur_layer.len() > 1 {
            let is_sibling_left = position % 2 != 0;
            let sibling_position = if is_sibling_left {
                position - 1
            } else {
                position + 1
            };
            merkle_path.push((cur_layer[sibling_position], is_sibling_left));

            cur_layer = cur_layer
                .chunks(2)
                .map(|pair| hash_two(&pair[0], &pair[1]))
                .collect();
            position /= 2;
        }

        Ok(MerklePath::from_path(&merkle_path))
    }

    /// Checks if the action tree is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    fn padded_leaves(&self) -> Result<Vec<Digest>, ArmError> {
        if self.is_empty() {
            return Err(ArmError::EmptyTree);
        }

        let len = self
            .leaves
            .len()
            .checked_next_power_of_two()
            .ok_or(ArmError::TreeTooLarge)?;
        let mut leaves = self.leaves.clone();
        leaves.resize(len, *PADDING_LEAF);
        Ok(leaves)
    }
}

impl From<Vec<Digest>> for ActionTree {
    fn from(leaves: Vec<Digest>) -> Self {
        ActionTree::new(leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Digest {
        Digest::from([byte; 32])
    }

    #[test]
    fn generated_path_reconstructs_root() {
        let leaves = vec![digest(1), digest(2), digest(3)];
        let tree = ActionTree::new(leaves.clone());
        let root = tree.root().unwrap();

        for leaf in &leaves {
            let path = tree.generate_path(leaf).unwrap();
            assert_eq!(path.root(leaf), root);
        }
    }

    #[test]
    fn last_leaf_sibling_is_padding_for_unbalanced_tree() {
        // Three leaves pad to four; the last leaf's sibling at the bottom layer
        // must be PADDING_LEAF, and the resulting path must still reconstruct
        // the root.
        let leaves = vec![digest(1), digest(2), digest(3)];
        let tree = ActionTree::new(leaves.clone());
        let path = tree.generate_path(&digest(3)).unwrap();

        let (sibling, is_left) = path.0[0];
        assert_eq!(sibling, *PADDING_LEAF);
        assert!(!is_left, "padding sibling must sit on the right of leaf 3");
        assert_eq!(path.root(&digest(3)), tree.root().unwrap());
    }

    #[test]
    fn rejects_empty_tree_and_padding_leaf_paths() {
        let empty = ActionTree::new(Vec::new());
        assert_eq!(empty.root(), Err(ArmError::EmptyTree));
        assert_eq!(empty.generate_path(&digest(1)), Err(ArmError::EmptyTree));

        let tree = ActionTree::new(vec![digest(1)]);
        assert_eq!(
            tree.generate_path(&PADDING_LEAF),
            Err(ArmError::InvalidLeaf)
        );
    }
}
