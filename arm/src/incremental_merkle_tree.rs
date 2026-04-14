//! Incremental Merkle tree for efficient append-only updates.
//!
//! An [`IncrementalMerkleTree`] of depth `D` stores only `D` frontier nodes
//! (called `branch`) rather than all `2^D` leaves.  Each new leaf can
//! therefore be appended in O(D) time, and an authentication path is produced
//! at insertion time without rebuilding the whole tree.
//!
//! # Algorithm — binary addition
//!
//! Insertion behaves like binary addition on `count` (the number of leaves
//! inserted so far).  For each level, the lowest bit of `count` tells us
//! whether the new node is a left or right child:
//!
//! ```text
//! node = new_leaf
//! index = count
//!
//! for level in 0..depth:
//!     if index % 2 == 0:
//!         branch[level] = node   // cache the left child
//!         break                  // nothing to merge yet
//!     else:
//!         node = H(branch[level], node)  // merge with cached left
//!         index = index / 2
//!
//! count += 1
//! ```
//!
//! # Storage
//!
//! | field | description |
//! |-------|-------------|
//! | `branch[i]` | latest completed sub-tree root at level `i` |
//! | `count` | number of leaves inserted so far |
//! | `root` | cached current root, recomputed after each insert |
//!
//! Empty-subtree hashes (`ZEROS[i]`) are precomputed once at startup as a
//! module-level constant and shared across all tree instances.

use crate::{
    error::ArmError,
    merkle_path::{padding_leaf, MerklePath},
    utils::{core_to_risc0_digest, hash_two, risc0_to_core_digest},
    Digest,
};

/// Maximum depth an [`IncrementalMerkleTree`] may grow to.
pub const MAX_DEPTH: usize = 32;

lazy_static::lazy_static! {
    /// Precomputed empty-subtree hashes.  `ZEROS[i]` is the root of a
    /// fully-empty sub-tree of height `i`:
    ///   `ZEROS[0]` = canonical empty-leaf hash,
    ///   `ZEROS[i]` = `H(ZEROS[i-1], ZEROS[i-1])`.
    pub static ref ZEROS: [Digest; MAX_DEPTH] = {
        let mut z = [Digest::default(); MAX_DEPTH];
        z[0] = padding_leaf();
        for i in 1..MAX_DEPTH {
            z[i] = hash_core(&z[i - 1], &z[i - 1]);
        }
        z
    };
}

/// Hash two core [`Digest`]s together via the RISC0 SHA-256 implementation.
fn hash_core(left: &Digest, right: &Digest) -> Digest {
    let l = core_to_risc0_digest(left);
    let r = core_to_risc0_digest(right);
    risc0_to_core_digest(hash_two(&l, &r))
}

/// An incremental (append-only) Merkle tree whose depth grows on demand.
///
/// # Depth
///
/// The initial depth is set at construction time via [`IncrementalMerkleTree::new`]
/// and increases automatically whenever [`Self::insert`] would overflow the
/// current capacity.  Growth stops at [`MAX_DEPTH`].
///
/// # Memory
///
/// Only `depth` frontier digests (`branch`) plus one cached root are stored,
/// regardless of how many leaves have been inserted.  Empty-subtree hashes
/// are shared via the module-level [`ZEROS`] constant.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IncrementalMerkleTree {
    /// Height of the tree.
    depth: usize,
    /// `branch[i]` holds the latest completed sub-tree root at level `i`.
    /// Updated during insertion via the binary-addition carry algorithm.
    branch: Vec<Digest>,
    /// Cached current Merkle root; recomputed after every [`Self::insert`].
    root: Digest,
    /// Number of leaves inserted so far (= index of the next leaf).
    count: usize,
}

impl IncrementalMerkleTree {
    /// Creates a new, empty incremental Merkle tree with the given `depth`.
    ///
    /// Initialises `branch` from [`ZEROS`] and computes the root of the
    /// fully-empty tree.  Panics if `depth > MAX_DEPTH`.
    pub fn new(depth: usize) -> Self {
        let branch = ZEROS[..depth].to_vec();
        let root = Self::compute_root_inner(&branch, 0, depth);

        IncrementalMerkleTree {
            depth,
            branch,
            root,
            count: 0,
        }
    }

    /// Returns the depth of the tree.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Returns the current Merkle root.
    pub fn root(&self) -> Digest {
        self.root
    }

    /// Returns the number of leaves that have been inserted so far.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no leaves have been inserted yet.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the index at which the next leaf will be inserted.
    pub fn next_index(&self) -> usize {
        self.count
    }

    /// Maximum number of leaves this tree can hold at its current depth (`2^depth`).
    ///
    /// Always `Some` while `depth <= MAX_DEPTH` (32).
    pub fn capacity(&self) -> Option<usize> {
        1usize.checked_shl(self.depth as u32)
    }

    /// Returns the precomputed empty-subtree hashes up to the current depth.
    ///
    /// `zeros()[i]` is the root of a sub-tree of height `i` whose leaves are
    /// all the canonical empty-leaf ([`padding_leaf()`]).
    pub fn zeros(&self) -> &[Digest] {
        &ZEROS[..self.depth]
    }

    /// Returns a reference to the current frontier (branch) nodes.
    ///
    /// `branch()[i]` is the latest completed sub-tree root at level `i`.
    /// Together with [`ZEROS`] this captures the entire state needed to insert
    /// subsequent leaves.
    pub fn branch(&self) -> &[Digest] {
        &self.branch
    }

    /// Increases the tree depth by 1, doubling its capacity.
    ///
    /// The current root becomes the completed left subtree at the new level,
    /// and the right half is filled with the canonical empty subtree.
    /// All previously inserted leaves and their paths remain valid.
    ///
    /// # Errors
    ///
    /// Returns [`ArmError::TreeTooLarge`] if `depth` is already at [`MAX_DEPTH`].
    pub fn grow(&mut self) -> Result<(), ArmError> {
        if self.depth >= MAX_DEPTH {
            return Err(ArmError::TreeTooLarge);
        }
        let new_depth = self.depth + 1;

        // The current full subtree becomes the completed left child at the new level.
        self.branch.push(self.root);
        // New root = H(old_root, empty_right)
        self.root = hash_core(&self.root, &ZEROS[self.depth]);
        self.depth = new_depth;
        Ok(())
    }

    /// Inserts a new leaf and returns its index.
    ///
    /// Uses the binary-addition carry algorithm: walks from level 0 upward,
    /// merging with previously cached left sub-trees whenever `count` has a 1
    /// bit at that level, and storing the result at the first 0 bit.
    ///
    /// If the tree is at capacity, the depth is automatically increased by 1
    /// before insertion.
    ///
    /// # Errors
    ///
    /// Returns [`ArmError::TreeTooLarge`] if the tree is already at
    /// [`MAX_DEPTH`] and cannot grow further.
    pub fn insert(&mut self, leaf: Digest) -> Result<usize, ArmError> {
        if self.count >= self.capacity().ok_or(ArmError::TreeTooLarge)? {
            self.grow()?;
        }

        let leaf_index = self.count;
        let mut node = leaf;
        let mut index = self.count;
        let mut merged_all = true;

        for level in 0..self.depth {
            if index % 2 == 0 {
                // Left child: cache this node and stop — nothing to merge yet.
                self.branch[level] = node;
                merged_all = false;
                break;
            } else {
                // Right child: merge with the cached left sub-tree and carry.
                node = hash_core(&self.branch[level], &node);
                index /= 2;
            }
        }

        self.count += 1;

        if merged_all && self.depth > 0 {
            // All levels carried: `node` is the root of the now-full tree.
            self.root = node;
        } else {
            // Recompute the cached root from the updated branch/count.
            self.root = Self::compute_root_inner(&self.branch, self.count, self.depth);
        }
        Ok(leaf_index)
    }

    /// Returns the authentication path for the leaf that will be inserted
    /// *next* (at `self.next_index()`), without modifying the tree.
    ///
    /// The returned path is valid against the root that will exist *after* the
    /// subsequent [`Self::insert`] call.  Prefer [`Self::insert_and_get_path`]
    /// when both operations are needed together.
    ///
    /// # Path encoding
    ///
    /// Each entry `(sibling, is_sibling_left)` describes one level:
    /// * `is_sibling_left = false` — the sibling is to the right of the
    ///   current node (current node is a left child).
    /// * `is_sibling_left = true` — the sibling is to the left (current node
    ///   is a right child).
    ///
    /// # Errors
    ///
    /// Returns [`ArmError::TreeTooLarge`] if the tree is already at capacity.
    pub fn next_path(&self) -> Result<MerklePath, ArmError> {
        let capacity = self.capacity().ok_or(ArmError::TreeTooLarge)?;
        if self.count >= capacity {
            return Err(ArmError::TreeTooLarge);
        }

        let mut path = Vec::with_capacity(self.depth);
        let mut idx = self.count;

        for level in 0..self.depth {
            let entry = if idx % 2 == 0 {
                // Left child: the right sibling is an empty sub-tree
                (ZEROS[level], false)
            } else {
                // Right child: the left sibling is the last completed left sub-tree
                (self.branch[level], true)
            };
            path.push(entry);
            idx >>= 1;
        }

        Ok(MerklePath::from_path(&path))
    }

    /// Inserts a new leaf and simultaneously returns the authentication path
    /// for that leaf against the updated root.
    ///
    /// Equivalent to calling [`Self::next_path`] followed by [`Self::insert`],
    /// and guarantees that `path.root(&leaf) == self.root()` holds after the
    /// call.
    ///
    /// # Returns
    ///
    /// `Ok((leaf_index, path))` where:
    /// * `leaf_index` is the position of the inserted leaf.
    /// * `path` is the authentication path satisfying `path.root(&leaf) == self.root()`.
    ///
    /// # Errors
    ///
    /// Returns [`ArmError::TreeTooLarge`] if the tree is already at [`MAX_DEPTH`]
    /// and cannot grow further.
    pub fn insert_and_get_path(&mut self, leaf: Digest) -> Result<(usize, MerklePath), ArmError> {
        // Grow before computing the path so both see the same depth.
        if self.count >= self.capacity().ok_or(ArmError::TreeTooLarge)? {
            self.grow()?;
        }
        let path = self.next_path()?;
        let idx = self.insert(leaf)?;
        Ok((idx, path))
    }

    /// Recomputes the Merkle root from `branch` and `count`.
    ///
    /// Walks from level 0 to `depth-1`.  At each level, if the corresponding
    /// bit of `count` is set, `branch[level]` is a completed left sub-tree
    /// that goes on the left; otherwise the running hash goes on the left and
    /// `ZEROS[level]` fills the empty right slot.
    fn compute_root_inner(branch: &[Digest], count: usize, depth: usize) -> Digest {
        if depth == 0 {
            return padding_leaf();
        }

        let mut current = ZEROS[0];
        for level in 0..depth {
            if count & (1 << level) != 0 {
                current = hash_core(&branch[level], &current);
            } else {
                current = hash_core(&current, &ZEROS[level]);
            }
        }
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_path::MerklePathExt;

    fn small_tree() -> IncrementalMerkleTree {
        IncrementalMerkleTree::new(3)
    }

    // ── construction ─────────────────────────────────────────────────────────

    #[test]
    fn empty_tree_has_deterministic_root() {
        let t1 = small_tree();
        let t2 = small_tree();
        assert_eq!(t1.root(), t2.root());
        assert_ne!(t1.root(), Digest::default());
    }

    // ── capacity ──────────────────────────────────────────────────────────────

    #[test]
    fn capacity_is_power_of_two() {
        assert_eq!(IncrementalMerkleTree::new(0).capacity(), Some(1));
        assert_eq!(IncrementalMerkleTree::new(1).capacity(), Some(2));
        assert_eq!(IncrementalMerkleTree::new(3).capacity(), Some(8));
        assert_eq!(IncrementalMerkleTree::new(10).capacity(), Some(1024));
    }

    // ── bookkeeping ───────────────────────────────────────────────────────────

    #[test]
    fn len_and_is_empty() {
        let mut tree = small_tree();
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);

        let leaf = Digest::new([1, 0, 0, 0, 0, 0, 0, 0]);
        tree.insert(leaf).unwrap();
        assert!(!tree.is_empty());
        assert_eq!(tree.len(), 1);
        assert_eq!(tree.next_index(), 1);
    }

    // ── overflow guard ────────────────────────────────────────────────────────

    #[test]
    fn next_path_at_capacity_returns_error() {
        let mut tree = IncrementalMerkleTree::new(2);
        let leaf = Digest::new([1, 0, 0, 0, 0, 0, 0, 0]);
        for _ in 0..4 {
            tree.insert(leaf).unwrap();
        }
        assert!(matches!(tree.next_path(), Err(ArmError::TreeTooLarge)));
    }

    // ── maximum depth ────────────────────────────────────────────────────────

    #[test]
    fn grow_at_max_depth_returns_error() {
        let mut tree = IncrementalMerkleTree::new(MAX_DEPTH);
        assert!(matches!(tree.grow(), Err(ArmError::TreeTooLarge)));
    }

    // ── dynamic growth ────────────────────────────────────────────────────────

    #[test]
    fn insert_auto_grows_at_capacity() {
        let mut tree = IncrementalMerkleTree::new(2);
        let leaf = Digest::new([7, 0, 0, 0, 0, 0, 0, 0]);
        // Fill the depth-2 tree (4 leaves)
        for _ in 0..4 {
            tree.insert(leaf).unwrap();
        }
        assert_eq!(tree.depth(), 2);
        assert_eq!(tree.len(), 4);

        // 5th insert should auto-grow to depth 3
        tree.insert(leaf).unwrap();
        assert_eq!(tree.depth(), 3);
        assert_eq!(tree.len(), 5);
    }

    #[test]
    fn grown_tree_paths_verify() {
        let mut tree = IncrementalMerkleTree::new(1);
        // Fill depth-1 (2 leaves), then insert 2 more — triggering two grows
        for i in 0..4u32 {
            let leaf = Digest::new([i + 1, 0, 0, 0, 0, 0, 0, 0]);
            let (_, path) = tree.insert_and_get_path(leaf).unwrap();
            assert_eq!(
                path.root(&leaf),
                tree.root(),
                "leaf {i}: path mismatch after grow"
            );
        }
        assert_eq!(tree.depth(), 2);
    }

    #[test]
    fn explicit_grow_doubles_capacity() {
        let mut tree = IncrementalMerkleTree::new(3);
        assert_eq!(tree.capacity(), Some(8));
        tree.grow().unwrap();
        assert_eq!(tree.depth(), 4);
        assert_eq!(tree.capacity(), Some(16));
    }

    #[test]
    fn grow_on_empty_tree_preserves_root() {
        let mut tree = IncrementalMerkleTree::new(2);
        let root_before = tree.root();
        tree.grow().unwrap();
        // Growing an empty tree: new root = H(old_root, ZEROS[2])
        let expected = hash_core(&root_before, &ZEROS[2]);
        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn insertions_after_grow_verify() {
        // Fill a depth-2 tree, let it auto-grow, and confirm all paths verify.
        let mut tree = IncrementalMerkleTree::new(2);
        for i in 0..8u32 {
            let leaf = Digest::new([i + 1, 0, 0, 0, 0, 0, 0, 0]);
            let (_, path) = tree.insert_and_get_path(leaf).unwrap();
            assert_eq!(
                path.root(&leaf),
                tree.root(),
                "leaf {i}: path mismatch (depth {})",
                tree.depth()
            );
        }
        // Grew once: depth 2 → 3 (capacity 4 → 8), exactly fits 8 leaves
        assert_eq!(tree.depth(), 3);
        assert_eq!(tree.len(), 8);
    }

    // ── single insertion ──────────────────────────────────────────────────────

    #[test]
    fn single_insertion_path_verifies() {
        let mut tree = small_tree();
        let leaf = Digest::new([1, 2, 3, 4, 5, 6, 7, 8]);

        let (idx, path) = tree.insert_and_get_path(leaf).unwrap();

        assert_eq!(idx, 0);
        assert_eq!(path.len(), 3);
        assert_eq!(path.root(&leaf), tree.root());
    }

    // ── multiple insertions ───────────────────────────────────────────────────

    #[test]
    fn all_paths_verify_at_insert_time() {
        let mut tree = small_tree();
        for i in 0..8u32 {
            let leaf = Digest::new([i, 0, 0, 0, 0, 0, 0, 0]);
            let (_, path) = tree.insert_and_get_path(leaf).unwrap();
            assert_eq!(
                path.root(&leaf),
                tree.root(),
                "leaf {i}: path root mismatch"
            );
        }
    }

    // ── next_path / insert consistency ───────────────────────────────────────

    #[test]
    fn next_path_and_insert_and_get_path_agree() {
        let leaf = Digest::new([42, 0, 0, 0, 0, 0, 0, 0]);

        // Method 1: call next_path() then insert()
        let mut tree1 = small_tree();
        let path1 = tree1.next_path().unwrap();
        tree1.insert(leaf).unwrap();

        // Method 2: call insert_and_get_path()
        let mut tree2 = small_tree();
        let (_, path2) = tree2.insert_and_get_path(leaf).unwrap();

        assert_eq!(path1, path2);
        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn next_path_verifies_after_insert() {
        let mut tree = small_tree();
        for i in 0..8u32 {
            let leaf = Digest::new([i, 0, 0, 0, 0, 0, 0, 0]);
            let path = tree.next_path().unwrap();
            tree.insert(leaf).unwrap();
            assert_eq!(path.root(&leaf), tree.root(), "leaf {i}: path mismatch");
        }
    }

    // ── root changes after each insertion ────────────────────────────────────

    #[test]
    fn root_changes_after_each_insertion() {
        let mut tree = small_tree();
        let initial_root = tree.root();

        let leaf_a = Digest::new([1, 0, 0, 0, 0, 0, 0, 0]);
        tree.insert(leaf_a).unwrap();
        let root_after_first = tree.root();
        assert_ne!(root_after_first, initial_root);

        let leaf_b = Digest::new([2, 0, 0, 0, 0, 0, 0, 0]);
        tree.insert(leaf_b).unwrap();
        assert_ne!(tree.root(), root_after_first);
    }

    // ── distinct leaves produce distinct roots ────────────────────────────────

    #[test]
    fn distinct_leaves_produce_distinct_roots() {
        let leaf_a = Digest::new([1, 0, 0, 0, 0, 0, 0, 0]);
        let leaf_b = Digest::new([2, 0, 0, 0, 0, 0, 0, 0]);

        let mut tree_a = small_tree();
        tree_a.insert(leaf_a).unwrap();

        let mut tree_b = small_tree();
        tree_b.insert(leaf_b).unwrap();

        assert_ne!(tree_a.root(), tree_b.root());
    }

    // ── binary-addition carry ────────────────────────────────────────────────

    #[test]
    fn branch_reflects_binary_carry_pattern() {
        let mut tree = IncrementalMerkleTree::new(3);
        let leaves: Vec<Digest> = (0..4u32)
            .map(|i| Digest::new([i + 1, 0, 0, 0, 0, 0, 0, 0]))
            .collect();

        // After 1 insertion (count=1, binary 001): branch[0] = L0
        tree.insert(leaves[0]).unwrap();
        assert_eq!(tree.branch()[0], leaves[0]);

        // After 2 insertions (count=2, binary 010): branch[1] = H(L0, L1)
        tree.insert(leaves[1]).unwrap();
        let h01 = hash_core(&leaves[0], &leaves[1]);
        assert_eq!(tree.branch()[1], h01);

        // After 3 insertions (count=3, binary 011): branch[0] = L2
        tree.insert(leaves[2]).unwrap();
        assert_eq!(tree.branch()[0], leaves[2]);

        // After 4 insertions (count=4, binary 100): branch[2] = H(H(L0,L1), H(L2,L3))
        tree.insert(leaves[3]).unwrap();
        let h23 = hash_core(&leaves[2], &leaves[3]);
        let h0123 = hash_core(&h01, &h23);
        assert_eq!(tree.branch()[2], h0123);
    }

    // ── full tree ────────────────────────────────────────────────────────────

    #[test]
    fn full_tree_root_is_correct() {
        let mut tree = IncrementalMerkleTree::new(2);
        let leaves: Vec<Digest> = (0..4u32)
            .map(|i| Digest::new([i + 1, 0, 0, 0, 0, 0, 0, 0]))
            .collect();

        for leaf in &leaves {
            tree.insert(*leaf).unwrap();
        }

        // Manually compute the expected root
        let h01 = hash_core(&leaves[0], &leaves[1]);
        let h23 = hash_core(&leaves[2], &leaves[3]);
        let expected_root = hash_core(&h01, &h23);
        assert_eq!(tree.root(), expected_root);
    }

    // ── depth-0 edge case ────────────────────────────────────────────────────

    #[test]
    fn depth_zero_tree() {
        let tree = IncrementalMerkleTree::new(0);
        assert_eq!(tree.capacity(), Some(1));
        assert_eq!(tree.root(), padding_leaf());
    }

    // ── path depth matches tree depth ────────────────────────────────────────

    #[test]
    fn path_length_equals_depth() {
        let mut tree = small_tree();
        let leaf = Digest::new([5, 0, 0, 0, 0, 0, 0, 0]);
        let (_, path) = tree.insert_and_get_path(leaf).unwrap();
        assert_eq!(path.len(), 3);
    }

    // ── depth-10 tree ────────────────────────────────────────────────────────

    #[test]
    fn depth_10_tree_works() {
        let mut tree = IncrementalMerkleTree::new(10);
        assert_eq!(tree.capacity(), Some(1024));

        let leaf = Digest::new([1, 2, 3, 4, 5, 6, 7, 8]);
        let (idx, path) = tree.insert_and_get_path(leaf).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(path.len(), 10);
        assert_eq!(path.root(&leaf), tree.root());
    }

    // ── consistency with existing MerkleTree ─────────────────────────────────

    #[test]
    fn matches_action_tree_root() {
        use crate::action_tree::MerkleTree;

        let leaves: Vec<Digest> = (0..5u32)
            .map(|i| Digest::new([i + 1, 0, 0, 0, 0, 0, 0, 0]))
            .collect();

        // Build the same tree with both implementations
        let full_tree = MerkleTree::new(leaves.clone());
        let mut inc_tree = IncrementalMerkleTree::new(3);
        for leaf in &leaves {
            inc_tree.insert(*leaf).unwrap();
        }

        assert_eq!(full_tree.root().unwrap(), inc_tree.root());
    }
}
