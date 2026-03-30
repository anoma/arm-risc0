//! Execution proof types for verifying a batch of transactions against shared
//! commitment and nullifier state.
//!
//! The circuit takes an [`ExecutionProofWitness`] and produces an
//! [`ExecutionProofInstance`] committed to the RISC0 journal.  For each
//! transaction it checks:
//!
//! 1. **Nullifier uniqueness** — no two compliance units in the batch consume
//!    the same nullifier, checked via sort + adjacent comparison.
//! 2. **Delta proof** — the transaction's delta proof is valid.
//! 3. **Aggregation proof** — all compliance and logic proofs within the
//!    transaction have been aggregated and verified against
//!    [`ExecutionProofWitness::batch_aggregation_vk`] and
//!    [`ExecutionProofWitness::compliance_vk`].  For each resource the
//!    circuit also asserts that the logic verifier input's `verifying_key`
//!    matches the `logic_ref` committed in the corresponding compliance
//!    instance, and collects [`ResourceAppData`] for consumed and created
//!    resources.
//! 4. **Nullifier non-membership + insertion** — each consumed nullifier is
//!    absent from the indexed nullifier tree ([`InsertionWitness::apply`]
//!    proves non-membership and returns the updated root atomically).
//! 5. **Commitment insertion** — each created commitment is appended to the
//!    incremental commitment tree.
//!
//! The resulting [`ExecutionProofInstance`] binds the pre- and post-batch
//! tree roots, the per-resource application data, and the verifying keys used
//! during verification, so downstream verifiers can chain proofs and inspect
//! resource payloads without re-running the circuit.

use crate::{
    incremental_merkle_tree::IncrementalMerkleTree, indexed_merkle_tree::InsertionWitness, AppData,
    Digest, Transaction,
};
use serde::{Deserialize, Serialize};

/// Application data associated with a single resource in the execution proof.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceAppData {
    /// The resource tag (nullifier for consumed, commitment for created).
    pub tag: Digest,
    /// The verifying key of the resource's logic proof.
    pub vk: Digest,
    /// The application data payload for this resource.
    pub app_data: AppData,
}

/// Public outputs of the execution proof, committed to the RISC0 journal.
///
/// Downstream verifiers chain proofs by checking that
/// `old_commitment_tree_root` and `old_nullifier_tree_root` of a later proof
/// match the outputs of the preceding one.  The committed `batch_aggregation_vk`
/// and `compliance_vk` make the verifying keys that were used during proof
/// verification an explicit part of the instance, binding them to the journal.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionProofInstance {
    /// Commitment tree root before the batch was executed.
    pub old_commitment_tree_root: Digest,
    /// Nullifier tree root before the batch was executed.
    pub old_nullifier_tree_root: Digest,
    /// Commitment tree root after executing the batch.
    pub new_commitment_root: Digest,
    /// Nullifier tree root after executing the batch.
    pub new_nullifier_tree_root: Digest,
    /// Application data for each consumed resource in this execution batch.
    pub consumed_resource_app_data: Vec<ResourceAppData>,
    /// Application data for each created resource in this execution batch.
    pub created_resource_app_data: Vec<ResourceAppData>,
    /// Verifying key for the batch aggregation circuit.
    pub batch_aggregation_vk: Digest,
    /// Verifying key for the compliance circuit.
    pub compliance_vk: Digest,
}

/// Private witness consumed by the execution proof circuit.
///
/// Commitment updates are driven by [`commitment_tree`], whose state is
/// advanced by `insert` for each created commitment.  Nullifier updates are
/// driven by [`nullifier_witnesses`], one per compliance unit — each witness
/// simultaneously proves non-membership of the consumed nullifier and derives
/// the new nullifier root via [`InsertionWitness::apply`].
///
/// The [`batch_aggregation_vk`] and [`compliance_vk`] are passed in rather
/// than hardcoded, so the circuit can be used with different deployments.
///
/// [`commitment_tree`]: ExecutionProofWitness::commitment_tree
/// [`nullifier_witnesses`]: ExecutionProofWitness::nullifier_witnesses
/// [`batch_aggregation_vk`]: ExecutionProofWitness::batch_aggregation_vk
/// [`compliance_vk`]: ExecutionProofWitness::compliance_vk
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
    /// Verifying key for the batch aggregation circuit.
    pub batch_aggregation_vk: Digest,
    /// Verifying key for the compliance circuit.
    pub compliance_vk: Digest,
}
