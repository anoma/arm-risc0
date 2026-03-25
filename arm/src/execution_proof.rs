//! Execution proof types for verifying a batch of transactions against shared
//! commitment and nullifier state.
//!
//! The circuit takes an [`ExecutionProofWitness`] and produces an
//! [`ExecutionProofInstance`] committed to the RISC0 journal.  For each
//! transaction it checks:
//!
//! 1. **Nullifier uniqueness** — no two compliance units in the batch consume
//!    the same nullifier. It also implies that all commimtments are unique.
//! 2. **Delta proof** — the transaction's delta proof is valid.
//! 3. **Aggregation proof** — all compliance and logic proofs within the
//!    transaction have been aggregated and verified.
//! 4. **Nullifier non-membership + insertion** — each consumed nullifier is
//!    absent from the indexed nullifier tree ([`InsertionWitness::apply`]
//!    proves non-membership and returns the updated root atomically).
//! 5. **Commitment insertion** — each created commitment is appended to the
//!    incremental commitment tree.

use crate::{
    incremental_merkle_tree::IncrementalMerkleTree, indexed_merkle_tree::InsertionWitness, Digest,
    Transaction,
};
use serde::{Deserialize, Serialize};

/// Public outputs of the execution proof, committed to the journal.
///
/// Downstream verifiers chain proofs by checking that
/// `old_commitment_tree_root` and `old_nullifier_tree_root` of a later proof
/// match the outputs of the preceding one.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionProofInstance {
    /// Commitment tree root before the batch was executed.
    pub old_commitment_tree_root: Digest,
    /// Nullifier tree root before the batch was executed.
    pub old_nullifier_tree_root: Digest,
    /// Full commitment tree state after executing the batch.
    ///
    /// Carries the incremental tree so the next proof can continue inserting
    /// commitments without re-proving the prior state.
    /// `new_commitment_tree.root()` gives the updated commitment root.
    pub new_commitment_tree: IncrementalMerkleTree,
    /// Nullifier tree root after executing the batch.
    pub new_nullifier_tree_root: Digest,
}

/// Private witness consumed by the execution proof circuit.
///
/// Commitment updates are driven by [`commitment_tree`], whose state is
/// advanced by `insert` for each created commitment.  Nullifier updates are
/// driven by [`nullifier_witnesses`], one per compliance unit — each witness
/// simultaneously proves non-membership of the consumed nullifier and derives
/// the new nullifier root via [`InsertionWitness::apply`].
///
/// [`commitment_tree`]: ExecutionProofWitness::commitment_tree
/// [`nullifier_witnesses`]: ExecutionProofWitness::nullifier_witnesses
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionProofWitness {
    /// The transactions to execute and verify.
    pub transactions: Vec<Transaction>,
    /// Incremental commitment tree state before the batch.
    pub commitment_tree: IncrementalMerkleTree,
    /// Indexed nullifier tree root before the batch.
    pub old_nullifier_tree_root: Digest,
    /// Nullifier insertion witnesses in transaction → action → compliance-unit
    /// order; one entry per compliance unit across the entire batch.
    ///
    /// Each [`InsertionWitness`] proves that the consumed nullifier is absent
    /// from the current nullifier tree root and returns the root after
    /// insertion, threading state forward to the next witness.
    pub nullifier_witnesses: Vec<InsertionWitness>,
}
