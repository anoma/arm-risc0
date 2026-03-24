//! Execution proof types for verifying transaction execution and state transitions.
//!
//! The execution proof circuit verifies a batch of transactions and produces
//! the updated commitment and nullifier tree roots. For each transaction it checks:
//! - No duplicate nullifiers within the batch
//! - The delta proof is valid
//! - The batch aggregation proof is valid
//! - Every consumed nullifier is absent from the old nullifier tree (non-inclusion),
//!   proven via the nullifier sibling path leading to an empty leaf
//!
//! After verification it uses sibling paths to incrementally update both tree roots.

use crate::{Digest, MerklePath, Transaction};
use serde::{Deserialize, Serialize};

/// Public outputs of the execution proof, committed to the journal.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionProofInstance {
    /// Commitment tree root before executing the transactions.
    pub old_commitment_tree_root: Digest,
    /// Nullifier tree root before executing the transactions.
    pub old_nullifier_tree_root: Digest,
    /// Commitment tree root after executing the transactions.
    pub new_commitment_tree_root: Digest,
    /// Nullifier tree root after executing the transactions.
    pub new_nullifier_tree_root: Digest,
}

/// Private witness for the execution proof circuit.
///
/// Tree roots are updated incrementally using sibling paths rather than by
/// rebuilding from the full leaf set. There must be exactly one path per
/// compliance unit, ordered by transaction → action → compliance unit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionProofWitness {
    /// The transactions to execute and verify.
    pub transactions: Vec<Transaction>,
    /// Commitment tree root before executing the transactions.
    ///
    /// Use `Digest::default()` (all zeros) when the commitment tree is empty.
    pub old_commitment_tree_root: Digest,
    /// Nullifier tree root before executing the transactions.
    ///
    /// Use `Digest::default()` (all zeros) when the nullifier tree is empty.
    pub old_nullifier_tree_root: Digest,
    /// Sibling paths for commitment insertions, one per compliance unit in
    /// transaction → action → compliance-unit order.
    ///
    /// Each path points to the empty slot where the created commitment will be
    /// appended.  The circuit verifies `path.root(padding_leaf()) ==
    /// current_commitment_root` before inserting.
    pub commitment_paths: Vec<MerklePath>,
    /// Sibling paths for nullifier insertions, one per compliance unit in
    /// transaction → action → compliance-unit order.
    ///
    /// Each path points to the empty slot where the consumed nullifier will be
    /// appended.  The circuit verifies `path.root(padding_leaf()) ==
    /// current_nullifier_root` as the non-inclusion proof, then derives the
    /// new root via `path.root(nullifier)`.
    pub nullifier_paths: Vec<MerklePath>,
}
