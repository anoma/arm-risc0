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
//! Inserting `v` with predecessor `(lo → hi)` requires exactly two tree
//! operations regardless of tree size:
//!
//! 1. **Predecessor update**: rewrite the predecessor leaf from `(lo → hi)`
//!    to `(lo → v)` via a Merkle path update.
//! 2. **New leaf append**: insert a new leaf `(v → hi)` at the next free slot.
//!
//! # Host vs circuit split
//!
//! [`IndexedMerkleTree`] is a **host-side** data structure.  It holds the full
//! leaf array and a [`BTreeMap`] secondary index for O(log n) predecessor
//! lookup, and it generates [`NonMembershipProof`]s and [`InsertionWitness`]es
//! that the circuit verifies cheaply without touching the full tree.
//!
//! | struct | where it runs | purpose |
//! |--------|---------------|---------|
//! | [`IndexedMerkleTree`] | host only | generates witnesses |
//! | [`NonMembershipProof`] | host + circuit | proves `v ∉ S` |
//! | [`InsertionWitness`] | host + circuit | proves non-membership and updates root |

use crate::{
    error::ArmError,
    incremental_merkle_tree::ZEROS,
    merkle_path::{padding_leaf, MerklePath, MerklePathExt},
    utils::{core_to_risc0_digest, hash_two, risc0_to_core_digest},
    Digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

lazy_static::lazy_static! {
    /// Minimum sentinel value (lower bound; always the first leaf).
    ///
    /// Equal to the all-zeros digest.  Real nullifiers are SHA-256 outputs and
    /// will never collide with this value.
    pub static ref MIN_VALUE: Digest = Digest::new([0u32; 8]);

    /// Maximum sentinel value (`∞`; upper bound of the last leaf's range).
    ///
    /// Equal to the all-`0xFFFFFFFF` digest.  Real nullifiers are SHA-256
    /// outputs and will never collide with this value.
    pub static ref MAX_VALUE: Digest = Digest::new([u32::MAX; 8]);
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Hashes two [`Digest`]s together via the RISC0 SHA-256 implementation.
fn hash_pair(left: &Digest, right: &Digest) -> Digest {
    risc0_to_core_digest(hash_two(
        &core_to_risc0_digest(left),
        &core_to_risc0_digest(right),
    ))
}

/// Returns `true` if `a < b` under a big-endian word-by-word comparison
/// (word 0 most significant).
///
/// This is identical to the lexicographic order that `[u32]::cmp` already
/// provides, so the implementation delegates directly to slice comparison.
fn digest_lt(a: &Digest, b: &Digest) -> bool {
    a.as_words() < b.as_words()
}

/// Newtype wrapper around [`Digest`] that exposes a total order consistent
/// with [`digest_lt`] (big-endian word-by-word comparison).
///
/// Used as the key type in [`IndexedMerkleTree::sorted_index`] so that a
/// [`BTreeMap`] can answer predecessor queries with `range(..key).next_back()`
/// in O(log n).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DigestKey(Digest);

impl PartialOrd for DigestKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DigestKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_words().cmp(other.0.as_words())
    }
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
/// The proof identifies the predecessor leaf `(lo → hi)` satisfying
/// `lo < target < hi` and provides its Merkle authentication path.  Because
/// the linked list is sorted and covers the entire value space, the existence
/// of such an interval is sufficient to conclude `target ∉ S`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonMembershipProof {
    /// Predecessor leaf satisfying `predecessor.value < target < predecessor.next_value`.
    pub predecessor: IndexedLeaf,
    /// Merkle path authenticating `predecessor` against the tree root.
    pub path: MerklePath,
}

impl NonMembershipProof {
    /// Verifies that `target` is not in the tree with the given `root`.
    ///
    /// Checks the interval bound `predecessor.value < target < predecessor.next_value`
    /// and that the predecessor is authenticated by `path` against `root`.
    ///
    /// Returns an error if any check fails.
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
/// Inserting `v` with predecessor `(lo → hi)` performs two operations:
///
/// 1. **Predecessor update**: rewrite `(lo → hi)` to `(lo → v)` in-place via
///    `predecessor_path`.
/// 2. **New leaf append**: insert `(v → hi)` at the next free slot via
///    `new_leaf_path`.
///
/// The two paths are computed at the *post-growth* depth: if the tree had to
/// grow to fit the new leaf, `grew = true` and both paths have length
/// `new_depth = old_depth + 1`.  [`apply`] accounts for this by first
/// reconstructing the grown root before checking `predecessor_path`.
///
/// [`apply`]: InsertionWitness::apply
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertionWitness {
    /// Predecessor leaf before insertion: `predecessor.value < v < predecessor.next_value`.
    pub predecessor: IndexedLeaf,
    /// Merkle path for the predecessor, valid against the *insertion root*.
    ///
    /// The insertion root is `old_root` when `grew = false`, or
    /// `H(old_root, ZEROS[old_depth])` when `grew = true`
    /// (where `old_depth = predecessor_path.len() - 1`).
    pub predecessor_path: MerklePath,
    /// Merkle path for the new leaf `(v → hi)`, valid against the
    /// *intermediate root* produced after rewriting the predecessor.
    pub new_leaf_path: MerklePath,
    /// `true` if the tree depth increased by 1 to accommodate the new leaf.
    pub grew: bool,
}

impl InsertionWitness {
    /// Verifies non-membership of `value`, applies the two-step insertion, and
    /// returns the new Merkle root.
    ///
    /// Steps performed in the circuit:
    ///
    /// 1. **Non-membership**: check `predecessor.value < value < predecessor.next_value`.
    /// 2. **Growth**: if `grew`, derive `insertion_root = H(old_root, ZEROS[old_depth])`.
    ///    Otherwise `insertion_root = old_root`.
    /// 3. **Predecessor authentication**: verify `predecessor_path` against
    ///    `insertion_root`.
    /// 4. **Predecessor update**: compute `intermediate_root` by rehashing the
    ///    path with the updated predecessor `(lo → value)`.
    /// 5. **Empty slot check**: verify `new_leaf_path` points to a padding leaf
    ///    in the tree at `intermediate_root`.
    /// 6. **New leaf**: return the root obtained by placing `(value → hi)` at
    ///    that slot.
    ///
    /// Returns an error if any step fails.
    pub fn apply(&self, value: &Digest, old_root: &Digest) -> Result<Digest, ArmError> {
        // Step 1 — non-membership interval check.
        if !digest_lt(&self.predecessor.value, value) {
            return Err(ArmError::ProofVerificationFailed(
                "insertion invalid: value ≤ predecessor value".into(),
            ));
        }
        if !digest_lt(value, &self.predecessor.next_value) {
            return Err(ArmError::NullifierDuplication);
        }

        // Step 2 — derive the root at insertion depth.
        //
        // When the tree grew, both paths were computed at `new_depth = old_depth + 1`.
        // We reconstruct the root at that depth by hashing the old root (the entire
        // left subtree) with `ZEROS[old_depth]` (an all-empty right subtree).
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

        // Step 3 — authenticate the predecessor.
        if self.predecessor_path.root(&self.predecessor.hash()) != insertion_root {
            return Err(ArmError::ProofVerificationFailed(
                "insertion invalid: predecessor path does not match root".into(),
            ));
        }

        // Step 4 — rewrite predecessor to `(lo → value)` and compute the
        // intermediate root.  Same path, different leaf hash.
        let updated_pred = IndexedLeaf {
            value: self.predecessor.value,
            next_value: *value,
        };
        let intermediate_root = self.predecessor_path.root(&updated_pred.hash());

        // Step 5 — verify the target slot is currently empty.
        if self.new_leaf_path.root(&padding_leaf()) != intermediate_root {
            return Err(ArmError::ProofVerificationFailed(
                "insertion invalid: new leaf slot is not empty".into(),
            ));
        }

        // Step 6 — place the new leaf `(value → hi)` and return the new root.
        let new_leaf = IndexedLeaf {
            value: *value,
            next_value: self.predecessor.next_value,
        };
        Ok(self.new_leaf_path.root(&new_leaf.hash()))
    }
}

// ── Host-side helpers ─────────────────────────────────────────────────────────

/// Builds a complete binary Merkle tree of the given `depth` from `leaf_hashes`.
///
/// Leaf positions `>= leaf_hashes.len()` are padded with [`padding_leaf()`].
/// Returns `layers` where `layers[0]` is the leaf level (width `2^depth`) and
/// `layers[depth]` is `[root]`.  Runs in O(2^depth) — host only.
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

/// Extracts a [`MerklePath`] for the leaf at `index` from a prebuilt layer
/// array produced by [`build_layers`].
///
/// Each path element is `(sibling_hash, is_right_child)`, where
/// `is_right_child = true` means the *current* node is a right child (sibling
/// is to the left), matching the [`MerklePath`] encoding used by
/// [`MerklePathExt::root`].
fn extract_path(layers: &[Vec<Digest>], index: usize) -> MerklePath {
    let depth = layers.len().saturating_sub(1);
    let mut path = Vec::with_capacity(depth);
    let mut idx = index;
    for level in &layers[..depth] {
        let is_right_child = idx % 2 == 1;
        let sibling_idx = if is_right_child { idx - 1 } else { idx + 1 };
        path.push((level[sibling_idx], is_right_child));
        idx /= 2;
    }
    MerklePath::from_path(&path)
}

// ── Host-side tree ────────────────────────────────────────────────────────────

/// Host-side indexed Merkle tree: generates [`NonMembershipProof`]s and
/// [`InsertionWitness`]es to be verified by the execution proof circuit.
///
/// Leaves are stored in **insertion order** (not sorted by value); the sorted
/// linked list is maintained through each leaf's `next_value` pointer.  Path
/// generation rebuilds the full tree from scratch on every call — O(2^depth)
/// — but this runs only on the host, never inside the circuit.
///
/// A `sorted_index` [`BTreeMap`] keyed by [`DigestKey`] provides O(log n)
/// predecessor lookup and O(log n) insertion (no element shifting).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedMerkleTree {
    /// Physical leaf array in insertion order.  Index 0 is always the
    /// `MIN_VALUE → MAX_VALUE` sentinel.
    leaves: Vec<IndexedLeaf>,
    /// Current Merkle tree depth.  Grows automatically when `leaves.len()`
    /// would exceed `2^depth`.
    depth: usize,
    /// Maps each leaf value to its physical index in `leaves`, kept in sorted
    /// order via [`DigestKey`] for O(log n) predecessor range queries.
    sorted_index: BTreeMap<DigestKey, usize>,
}

impl IndexedMerkleTree {
    /// Creates a new empty indexed Merkle tree.
    ///
    /// Seeds the tree with the sentinel leaf `(MIN_VALUE → MAX_VALUE)` at
    /// physical index 0, so every insertable value has a valid predecessor.
    pub fn new() -> Self {
        Self {
            leaves: vec![IndexedLeaf {
                value: *MIN_VALUE,
                next_value: *MAX_VALUE,
            }],
            depth: 0,
            sorted_index: BTreeMap::from([(DigestKey(*MIN_VALUE), 0)]),
        }
    }

    /// Returns the current Merkle root.
    pub fn root(&self) -> Digest {
        let hashes: Vec<Digest> = self.leaves.iter().map(|l| l.hash()).collect();
        // build_layers always returns depth+1 layers, each non-empty.
        build_layers(&hashes, self.depth)[self.depth][0]
    }

    /// Returns the number of leaves, including the [`MIN_VALUE`] sentinel.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Returns `true` if the tree contains only the sentinel leaf (no real
    /// values have been inserted).
    pub fn is_empty(&self) -> bool {
        self.leaves.len() == 1
    }

    /// Generates a [`NonMembershipProof`] showing that `value` is not in the
    /// tree.
    ///
    /// Returns an error if `value` is already in the set or equals
    /// [`MIN_VALUE`] (which has no valid predecessor).
    pub fn prove_non_membership(&self, value: &Digest) -> Result<NonMembershipProof, ArmError> {
        let pred_idx = self.predecessor_index(value)?;
        let predecessor = self.leaves[pred_idx].clone();
        // If value >= predecessor.next_value, value is already in the set.
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

    /// Inserts `value` into the tree and returns the [`InsertionWitness`].
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

        let n = self.leaves.len(); // physical index of the new leaf
        let grew = n + 1 > (1 << self.depth);
        let new_depth = if grew { self.depth + 1 } else { self.depth };

        // Build the tree at new_depth.  When grew=true this is the "insertion
        // root" depth; the extra right-subtree slots are all padding leaves.
        let current_hashes: Vec<Digest> = self.leaves.iter().map(|l| l.hash()).collect();
        let tree_before = build_layers(&current_hashes, new_depth);
        let predecessor_path = extract_path(&tree_before, pred_idx);

        // Rewrite the predecessor leaf hash and rebuild to get the intermediate
        // root (after step 1 of the two-step insertion).
        let mut updated_hashes = current_hashes;
        updated_hashes[pred_idx] = IndexedLeaf {
            value: predecessor.value,
            next_value: value,
        }
        .hash();
        let tree_after_update = build_layers(&updated_hashes, new_depth);
        // The new leaf lands at index n; its slot is currently a padding leaf.
        let new_leaf_path = extract_path(&tree_after_update, n);

        // Commit mutations.
        self.leaves[pred_idx].next_value = value;
        self.leaves.push(IndexedLeaf {
            value,
            next_value: predecessor.next_value,
        });
        self.depth = new_depth;
        self.sorted_index.insert(DigestKey(value), n);

        Ok(InsertionWitness {
            predecessor,
            predecessor_path,
            new_leaf_path,
            grew,
        })
    }

    /// Returns the physical index in `leaves` of the predecessor of `value`.
    ///
    /// The predecessor is the leaf whose value is the largest value strictly
    /// less than `value`.  Uses `BTreeMap::range(..key).next_back()` — O(log n).
    ///
    /// Returns [`ArmError::InvalidLeaf`] if no predecessor exists (i.e.
    /// `value ≤ MIN_VALUE`).
    fn predecessor_index(&self, value: &Digest) -> Result<usize, ArmError> {
        self.sorted_index
            .range(..DigestKey(*value))
            .next_back()
            .map(|(_, &idx)| idx)
            .ok_or(ArmError::InvalidLeaf)
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
        let l = IndexedLeaf {
            value: d(10),
            next_value: d(20),
        };
        assert_eq!(l.hash(), l.hash());
        assert_ne!(
            l.hash(),
            IndexedLeaf {
                value: d(10),
                next_value: d(30)
            }
            .hash()
        );
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

        // 20 is strictly between 10 and 30 → not in the set
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

        // Inserting the value changes the root.
        let old_root = tree.root();
        let witness = tree.insert(target).unwrap();
        let new_root = tree.root();
        assert_eq!(witness.apply(&target, &old_root).unwrap(), new_root);

        // 20 is now in the set; non-membership for 25 (between 20 and 30) still works.
        let proof2 = tree.prove_non_membership(&d(25)).unwrap();
        proof2.verify(&d(25), &tree.root()).unwrap();
    }

    #[test]
    fn insertion_triggers_tree_growth() {
        let mut tree = IndexedMerkleTree::new();

        // depth=0, capacity=1.  The sentinel occupies the only slot, so the
        // first real insertion must grow the tree to depth=1 (capacity=2).
        let w1 = tree.insert(d(1)).unwrap();
        assert!(w1.grew);
        assert_eq!(tree.depth, 1);

        // depth=1, capacity=2, leaves=[sentinel, d(1)].  The next insertion
        // needs a third slot, so the tree must grow again to depth=2.
        let old_root = tree.root();
        let w2 = tree.insert(d(2)).unwrap();
        assert!(w2.grew);
        assert_eq!(tree.depth, 2);
        assert_eq!(w2.apply(&d(2), &old_root).unwrap(), tree.root());
    }

    // ── build_layers / extract_path consistency ───────────────────────────────

    #[test]
    fn build_layers_root_matches_direct_hash() {
        let leaves = vec![d(1), d(2), d(3), d(4)];
        let layers = build_layers(&leaves, 2);
        let expected = hash_pair(&hash_pair(&d(1), &d(2)), &hash_pair(&d(3), &d(4)));
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
