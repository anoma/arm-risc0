//! Indexed Merkle tree for efficient nullifier non-membership proofs and insertion.
//!
//! An [`IndexedMerkleTree`] stores values in a **sorted linked list** committed
//! by a Merkle tree.  Every leaf records `(value, next_value)`, forming a chain
//! of intervals that together cover the entire value space from [`MIN_VALUE`] to
//! [`MAX_VALUE`].
//!
//! # Non-membership proof
//!
//! To prove `v ∉ S`, show the *predecessor* leaf `(lo → hi)` such that
//! `lo < v < hi`.  Since the chain is sorted and gapless, `v` cannot exist
//! elsewhere in the set.  The proof is:
//!
//! 1. A Merkle path proving `(lo → hi)` is in the tree.
//! 2. Range check: `lo < v < hi`.
//!
//! # Insertion
//!
//! Inserting `v` with predecessor `(lo → hi)`:
//!
//! 1. Update the predecessor leaf to `(lo → v)`.
//! 2. Append a new leaf `(v → hi)`.
//!
//! Only **one path update** and **one append** are needed regardless of tree size.
//!
//! # Storage
//!
//! | field | description |
//! |-------|-------------|
//! | `leaves` | physical leaf array in insertion order |
//! | `depth` | current Merkle tree depth (auto-grows) |

use crate::{
    error::ArmError,
    incremental_merkle_tree::ZEROS,
    merkle_path::{padding_leaf, MerklePath, MerklePathExt},
    utils::{core_to_risc0_digest, hash_two, risc0_to_core_digest},
    Digest,
};
use serde::{Deserialize, Serialize};

lazy_static::lazy_static! {
    /// Minimum sentinel value (lower bound; always the first leaf).
    ///
    /// Equal to the all-zeros digest.  Real nullifiers are SHA-256 outputs and
    /// will never equal this value.
    pub static ref MIN_VALUE: Digest = Digest::new([0u32; 8]);

    /// Maximum sentinel value (`∞`; upper bound of the last leaf's range).
    ///
    /// Equal to the all-`0xFFFFFFFF` digest.  Real nullifiers are SHA-256 outputs
    /// and will never equal this value.
    pub static ref MAX_VALUE: Digest = Digest::new([u32::MAX; 8]);
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn hash_pair(left: &Digest, right: &Digest) -> Digest {
    risc0_to_core_digest(hash_two(
        &core_to_risc0_digest(left),
        &core_to_risc0_digest(right),
    ))
}

/// Returns `true` if `a < b`, treating the `[u32; 8]` words as a big-endian
/// integer (word 0 is most significant).
fn digest_lt(a: &Digest, b: &Digest) -> bool {
    for (&wa, &wb) in a.as_words().iter().zip(b.as_words().iter()) {
        match wa.cmp(&wb) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    false // equal
}

// ── Public types ──────────────────────────────────────────────────────────────

/// A leaf in the indexed Merkle tree.
///
/// Each leaf records its own value and a pointer to the next-larger value in
/// the set, forming a sorted linked list across all leaves.  The leaf hash is
/// `H(value, next_value)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedLeaf {
    /// This leaf's value.
    pub value: Digest,
    /// The next-larger value in the set, or [`MAX_VALUE`] if this is the
    /// largest.
    pub next_value: Digest,
}

impl IndexedLeaf {
    /// Computes the leaf commitment hash: `H(value, next_value)`.
    pub fn hash(&self) -> Digest {
        hash_pair(&self.value, &self.next_value)
    }
}

/// Proof that a value is **not** in the indexed Merkle tree.
///
/// Identifies the predecessor leaf `(lo → hi)` with `lo < target < hi` and
/// provides its Merkle authentication path against the tree root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonMembershipProof {
    /// Predecessor leaf: `value < target < next_value`.
    pub predecessor: IndexedLeaf,
    /// Merkle path authenticating `predecessor` against the tree root.
    pub path: MerklePath,
}

impl NonMembershipProof {
    /// Verifies that `target` is not in the tree with the given `root`.
    ///
    /// Returns an error if the proof is invalid.
    pub fn verify(&self, target: &Digest, root: &Digest) -> Result<(), ArmError> {
        if !digest_lt(&self.predecessor.value, target) {
            return Err(ArmError::ProofVerificationFailed(
                "non-membership proof invalid: target ≤ predecessor value".into(),
            ));
        }
        if !digest_lt(target, &self.predecessor.next_value) {
            return Err(ArmError::ProofVerificationFailed(
                "non-membership proof invalid: target ≥ predecessor next_value".into(),
            ));
        }
        if self.path.root(&self.predecessor.hash()) != *root {
            return Err(ArmError::ProofVerificationFailed(
                "non-membership proof invalid: path does not match root".into(),
            ));
        }
        Ok(())
    }
}

/// Witness for inserting a single value into the indexed Merkle tree.
///
/// Inserting `v` with predecessor `(lo → hi)` performs two tree operations:
///
/// 1. Update predecessor from `(lo → hi)` to `(lo → v)` — path update.
/// 2. Append new leaf `(v → hi)` — incremental insert.
///
/// When the tree's depth increases to accommodate the new leaf, `grew = true`
/// and `predecessor_path` is computed at the new (larger) depth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertionWitness {
    /// Predecessor leaf before insertion.
    pub predecessor: IndexedLeaf,
    /// Merkle path for the predecessor leaf, valid against the *insertion root*.
    ///
    /// The insertion root equals `old_root` when `grew = false`, or
    /// `H(old_root, ZEROS[d - 1])` when `grew = true` (where
    /// `d = predecessor_path.len()`).
    pub predecessor_path: MerklePath,
    /// Merkle path for the new leaf `(v → hi)`, valid against the *intermediate
    /// root* (after updating the predecessor).
    pub new_leaf_path: MerklePath,
    /// `true` if the tree depth increased by 1 to fit the new leaf.
    pub grew: bool,
}

impl InsertionWitness {
    /// Verifies non-membership of `value`, applies the insertion, and returns
    /// the new Merkle root.
    ///
    /// Returns an error if the witness is inconsistent with `old_root`.
    pub fn apply(&self, value: &Digest, old_root: &Digest) -> Result<Digest, ArmError> {
        // --- Non-membership check ---
        if !digest_lt(&self.predecessor.value, value) {
            return Err(ArmError::ProofVerificationFailed(
                "insertion invalid: value ≤ predecessor value".into(),
            ));
        }
        if !digest_lt(value, &self.predecessor.next_value) {
            return Err(ArmError::NullifierDuplication);
        }

        // --- Compute root at insertion depth (account for possible growth) ---
        //
        // When the tree grew, the insertion root is H(old_root, ZEROS[old_depth])
        // where old_depth = predecessor_path.len() - 1 (the depth *before* growth).
        let insertion_root = if self.grew {
            let old_depth = self
                .predecessor_path
                .len()
                .checked_sub(1)
                .ok_or(ArmError::InvalidLeaf)?;
            hash_pair(old_root, &ZEROS[old_depth])
        } else {
            *old_root
        };

        // --- Verify predecessor exists at the insertion root ---
        if self.predecessor_path.root(&self.predecessor.hash()) != insertion_root {
            return Err(ArmError::ProofVerificationFailed(
                "insertion invalid: predecessor path does not match root".into(),
            ));
        }

        // --- Compute intermediate root after updating the predecessor ---
        let updated_pred = IndexedLeaf {
            value: self.predecessor.value,
            next_value: *value,
        };
        let intermediate_root = self.predecessor_path.root(&updated_pred.hash());

        // --- Verify the new leaf slot is currently empty ---
        if self.new_leaf_path.root(&padding_leaf()) != intermediate_root {
            return Err(ArmError::ProofVerificationFailed(
                "insertion invalid: new leaf slot is not empty".into(),
            ));
        }

        // --- Append new leaf and return the new root ---
        let new_leaf = IndexedLeaf {
            value: *value,
            next_value: self.predecessor.next_value,
        };
        Ok(self.new_leaf_path.root(&new_leaf.hash()))
    }
}

// ── Host-side helpers ─────────────────────────────────────────────────────────

/// Builds a complete Merkle tree of the given `depth` from `leaf_hashes`.
///
/// Positions `>= leaf_hashes.len()` are padded with [`padding_leaf()`].
/// Returns `layers` where `layers[0]` is the leaf level and
/// `layers[depth]` is `[root]`.
fn build_layers(leaf_hashes: &[Digest], depth: usize) -> Vec<Vec<Digest>> {
    let capacity = 1usize << depth;
    let mut level: Vec<Digest> = (0..capacity)
        .map(|i| leaf_hashes.get(i).copied().unwrap_or_else(padding_leaf))
        .collect();
    let mut layers = vec![level.clone()];
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| hash_pair(&pair[0], &pair[1]))
            .collect();
        layers.push(level.clone());
    }
    layers
}

/// Extracts a [`MerklePath`] for leaf `index` from a prebuilt layer array.
fn extract_path(layers: &[Vec<Digest>], index: usize) -> MerklePath {
    let depth = layers.len().saturating_sub(1);
    let mut path = Vec::with_capacity(depth);
    let mut idx = index;
    for level in &layers[..depth] {
        let is_right_child = idx % 2 == 1;
        let sibling_idx = if is_right_child { idx - 1 } else { idx + 1 };
        // second element: true = sibling is to the left (current is right child)
        path.push((level[sibling_idx], is_right_child));
        idx /= 2;
    }
    MerklePath::from_path(&path)
}

// ── Host-side tree ────────────────────────────────────────────────────────────

/// Host-side indexed Merkle tree: generates [`NonMembershipProof`]s and
/// [`InsertionWitness`]es.
///
/// Leaves are stored in **insertion order** (not sorted); the sorted linked
/// list is maintained through each leaf's `next_value` pointer.  Path
/// generation rebuilds the full Merkle tree at the current depth, which is
/// O(2^depth) but runs only on the host.
///
/// A secondary `sorted_index` — a `Vec<(Digest, usize)>` kept sorted by
/// `Digest` value — enables O(log n) predecessor lookup via binary search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedMerkleTree {
    /// Physical leaf array (insertion order).
    leaves: Vec<IndexedLeaf>,
    /// Current Merkle tree depth.
    depth: usize,
    /// Sorted index: `(leaf.value, physical_index_in_leaves)`, ordered by
    /// value using the same big-endian word comparison as [`digest_lt`].
    sorted_index: Vec<(Digest, usize)>,
}

impl IndexedMerkleTree {
    /// Creates a new empty indexed Merkle tree.
    ///
    /// Inserts the initial sentinel leaf `(MIN_VALUE → MAX_VALUE)` so that
    /// every real value has a valid predecessor.
    pub fn new() -> Self {
        Self {
            leaves: vec![IndexedLeaf {
                value: *MIN_VALUE,
                next_value: *MAX_VALUE,
            }],
            depth: 0,
            sorted_index: vec![(*MIN_VALUE, 0)],
        }
    }

    /// Returns the current Merkle root.
    pub fn root(&self) -> Digest {
        let hashes: Vec<Digest> = self.leaves.iter().map(|l| l.hash()).collect();
        // build_layers always returns at least one layer with at least one element.
        build_layers(&hashes, self.depth)[self.depth][0]
    }

    /// Returns the number of leaves (including the [`MIN_VALUE`] sentinel).
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Returns `true` if the tree contains only the sentinel leaf.
    pub fn is_empty(&self) -> bool {
        self.leaves.len() == 1
    }

    /// Generates a [`NonMembershipProof`] for `value`.
    ///
    /// Returns an error if `value` is already in the set or equals [`MIN_VALUE`].
    pub fn prove_non_membership(&self, value: &Digest) -> Result<NonMembershipProof, ArmError> {
        let pred_idx = self.predecessor_index(value)?;
        let predecessor = self.leaves[pred_idx].clone();
        if !digest_lt(value, &predecessor.next_value) {
            return Err(ArmError::NullifierDuplication);
        }
        let hashes: Vec<Digest> = self.leaves.iter().map(|l| l.hash()).collect();
        let layers = build_layers(&hashes, self.depth);
        Ok(NonMembershipProof {
            predecessor,
            path: extract_path(&layers, pred_idx),
        })
    }

    /// Inserts `value` and returns the [`InsertionWitness`].
    ///
    /// Returns an error if `value` is already in the set, equals [`MIN_VALUE`],
    /// or equals [`MAX_VALUE`].
    pub fn insert(&mut self, value: Digest) -> Result<InsertionWitness, ArmError> {
        if !digest_lt(&MIN_VALUE, &value) {
            return Err(ArmError::InvalidLeaf);
        }
        if !digest_lt(&value, &MAX_VALUE) {
            return Err(ArmError::InvalidLeaf);
        }

        let pred_idx = self.predecessor_index(&value)?;
        let predecessor = self.leaves[pred_idx].clone();
        if !digest_lt(&value, &predecessor.next_value) {
            return Err(ArmError::NullifierDuplication);
        }

        let n = self.leaves.len();
        let grew = n + 1 > (1 << self.depth);
        let new_depth = if grew { self.depth + 1 } else { self.depth };

        // predecessor_path at new_depth against the insertion root
        let current_hashes: Vec<Digest> = self.leaves.iter().map(|l| l.hash()).collect();
        let tree_before = build_layers(&current_hashes, new_depth);
        let predecessor_path = extract_path(&tree_before, pred_idx);

        // rebuild with updated predecessor, then get new_leaf_path
        let mut updated_hashes = current_hashes;
        updated_hashes[pred_idx] = IndexedLeaf {
            value: predecessor.value,
            next_value: value,
        }
        .hash();
        let tree_after_update = build_layers(&updated_hashes, new_depth);
        let new_leaf_path = extract_path(&tree_after_update, n);

        // apply mutation
        self.leaves[pred_idx].next_value = value;
        self.leaves.push(IndexedLeaf {
            value,
            next_value: predecessor.next_value,
        });
        self.depth = new_depth;
        let ins = self.sorted_index.partition_point(|(v, _)| digest_lt(v, &value));
        self.sorted_index.insert(ins, (value, n));

        Ok(InsertionWitness {
            predecessor,
            predecessor_path,
            new_leaf_path,
            grew,
        })
    }

    /// Returns the physical index of the predecessor leaf for `value`.
    ///
    /// Uses binary search on `sorted_index` (O(log n)): finds the last entry
    /// whose value is strictly less than `value`.
    fn predecessor_index(&self, value: &Digest) -> Result<usize, ArmError> {
        // partition_point returns the first position where the predicate is
        // false, i.e. the first entry with value >= target.  The predecessor
        // is the entry immediately before it.
        let pos = self.sorted_index.partition_point(|(v, _)| digest_lt(v, value));
        if pos == 0 {
            return Err(ArmError::InvalidLeaf);
        }
        Ok(self.sorted_index[pos - 1].1)
    }
}

impl Default for IndexedMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn d(v: u32) -> Digest {
        Digest::new([v, 0, 0, 0, 0, 0, 0, 0])
    }

    // ── digest_lt ────────────────────────────────────────────────────────────

    #[test]
    fn digest_lt_basic() {
        assert!(digest_lt(&d(1), &d(2)));
        assert!(!digest_lt(&d(2), &d(1)));
        assert!(!digest_lt(&d(1), &d(1)));
    }

    #[test]
    fn digest_lt_sentinels() {
        assert!(digest_lt(&*MIN_VALUE, &d(1)));
        assert!(digest_lt(&d(1), &*MAX_VALUE));
        assert!(!digest_lt(&*MAX_VALUE, &d(1)));
    }

    // ── IndexedLeaf::hash ────────────────────────────────────────────────────

    #[test]
    fn leaf_hash_is_deterministic() {
        let l = IndexedLeaf { value: d(10), next_value: d(20) };
        assert_eq!(l.hash(), l.hash());
        assert_ne!(l.hash(), IndexedLeaf { value: d(10), next_value: d(30) }.hash());
    }

    // ── non-membership proof ─────────────────────────────────────────────────

    #[test]
    fn non_membership_on_empty_tree() {
        let tree = IndexedMerkleTree::new();
        let target = d(42);
        let proof = tree.prove_non_membership(&target).unwrap();
        proof.verify(&target, &tree.root()).unwrap();
    }

    #[test]
    fn non_membership_after_insertions() {
        let mut tree = IndexedMerkleTree::new();
        tree.insert(d(10)).unwrap();
        tree.insert(d(30)).unwrap();

        // 20 is between 10 and 30 → not in set
        let target = d(20);
        let proof = tree.prove_non_membership(&target).unwrap();
        proof.verify(&target, &tree.root()).unwrap();
    }

    // ── insertion witness ────────────────────────────────────────────────────

    #[test]
    fn first_insertion_updates_root() {
        let mut tree = IndexedMerkleTree::new();
        let old_root = tree.root();
        let witness = tree.insert(d(42)).unwrap();
        let new_root = tree.root();

        assert_ne!(old_root, new_root);
        assert_eq!(witness.apply(&d(42), &old_root).unwrap(), new_root);
    }

    #[test]
    fn multiple_insertions_all_witnesses_valid() {
        let values = [d(10), d(50), d(30), d(20), d(40)];
        let mut tree = IndexedMerkleTree::new();

        for &v in &values {
            let old_root = tree.root();
            let witness = tree.insert(v).unwrap();
            let new_root = tree.root();
            assert_eq!(
                witness.apply(&v, &old_root).unwrap(),
                new_root,
                "witness invalid for value {:?}",
                v
            );
        }
    }

    #[test]
    fn non_membership_then_insertion_consistent() {
        let mut tree = IndexedMerkleTree::new();
        tree.insert(d(10)).unwrap();
        tree.insert(d(30)).unwrap();

        let target = d(20);
        let nm_proof = tree.prove_non_membership(&target).unwrap();
        nm_proof.verify(&target, &tree.root()).unwrap();

        // inserting the same value changes the root
        let old_root = tree.root();
        let witness = tree.insert(target).unwrap();
        let new_root = tree.root();
        assert_eq!(witness.apply(&target, &old_root).unwrap(), new_root);

        // 20 is now in the set; non-membership for 25 should still work
        let proof2 = tree.prove_non_membership(&d(25)).unwrap();
        proof2.verify(&d(25), &tree.root()).unwrap();
    }

    #[test]
    fn insertion_triggers_tree_growth() {
        let mut tree = IndexedMerkleTree::new();
        // depth=0 → capacity=1 (full with sentinel); first insert must grow
        let witness = tree.insert(d(1)).unwrap();
        assert!(witness.grew);
        assert_eq!(tree.depth, 1);

        // second insert stays at depth=1 (capacity=2, now has 3 leaves after sentinel)
        // actually depth=1 → capacity=2; with sentinel + 1 we have 2, full again
        let old_root = tree.root();
        let witness2 = tree.insert(d(2)).unwrap();
        assert!(witness2.grew); // 2+1=3 > 2^1=2 → must grow to depth 2
        assert_eq!(witness2.apply(&d(2), &old_root).unwrap(), tree.root());
    }

    // ── build_layers / extract_path consistency ───────────────────────────────

    #[test]
    fn build_layers_root_matches_direct_hash() {
        let leaves = vec![d(1), d(2), d(3), d(4)];
        let layers = build_layers(&leaves, 2);
        let expected = hash_pair(
            &hash_pair(&d(1), &d(2)),
            &hash_pair(&d(3), &d(4)),
        );
        assert_eq!(*layers.last().unwrap().first().unwrap(), expected);
    }

    #[test]
    fn extract_path_round_trips() {
        let leaves = vec![d(1), d(2), d(3), d(4)];
        let layers = build_layers(&leaves, 2);
        let root = *layers.last().unwrap().first().unwrap();
        for (i, &leaf) in leaves.iter().enumerate() {
            let path = extract_path(&layers, i);
            assert_eq!(path.root(&leaf), root, "path mismatch at index {i}");
        }
    }

    // ── error cases ───────────────────────────────────────────────────────────

    #[test]
    fn insert_min_value_returns_error() {
        let mut tree = IndexedMerkleTree::new();
        assert!(tree.insert(*MIN_VALUE).is_err());
    }

    #[test]
    fn insert_max_value_returns_error() {
        let mut tree = IndexedMerkleTree::new();
        assert!(tree.insert(*MAX_VALUE).is_err());
    }

    #[test]
    fn insert_duplicate_returns_error() {
        let mut tree = IndexedMerkleTree::new();
        tree.insert(d(42)).unwrap();
        assert!(tree.insert(d(42)).is_err());
    }

    #[test]
    fn non_membership_of_existing_value_returns_error() {
        let mut tree = IndexedMerkleTree::new();
        tree.insert(d(42)).unwrap();
        assert!(tree.prove_non_membership(&d(42)).is_err());
    }
}
