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
    ComplianceInstance, Delta, Digest, Transaction,
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

/// Compact logic verifier input for the execution proof circuit.
///
/// A stripped-down version of [`LogicVerifierInputs`] carrying only the three
/// fields the guest actually reads.  The `proof` bytes (potentially hundreds
/// of kilobytes) are deliberately omitted so they are never written to the
/// zkVM's input channel.
///
/// [`LogicVerifierInputs`]: crate::LogicVerifierInputs
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogicVerifierInfo {
    /// The resource tag (nullifier for consumed, commitment for created).
    pub tag: Digest,
    /// The verifying key of the resource's logic proof circuit.
    pub verifying_key: Digest,
    /// The application data payload for this resource.
    pub app_data: AppData,
}

/// Compact action data for the execution proof circuit.
///
/// Contains only the data the guest needs: the compliance instances (for delta
/// computation and aggregation instance construction) and the stripped logic
/// verifier inputs (for app-data collection and logic-ref consistency checks).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionInfo {
    /// Compliance instances for this action, one per compliance unit.
    pub compliance_instances: Vec<ComplianceInstance>,
    /// Logic verifier inputs stripped of their proof bytes.
    pub logic_verifier_inputs: Vec<LogicVerifierInfo>,
}

/// Compact transaction data for the execution proof circuit.
///
/// Replaces [`Transaction`] in [`ExecutionProofWitness`] so that only the
/// data the guest actually needs is serialised over the `env::write` channel.
/// The aggregation proof receipt (potentially megabytes as a full STARK
/// receipt) is excluded from serialisation via `#[serde(skip)]` and kept
/// host-side only, where it is registered with `add_assumption`.
///
/// [`Transaction`]: crate::Transaction
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInfo {
    /// Per-action compliance and logic data for this transaction.
    pub actions: Vec<ActionInfo>,
    /// The 65-byte ECDSA delta proof bytes.
    pub delta_proof: Vec<u8>,
    /// The serialised aggregation proof `InnerReceipt` (host-only).
    ///
    /// This field is skipped during serialisation so it is never written to
    /// the guest.  The host extracts it, deserialises it as an
    /// `InnerReceipt`, and registers it with `env_builder.add_assumption`.
    #[serde(skip)]
    pub aggregation_proof: Vec<u8>,
}

impl TxInfo {
    /// Converts a fully-proved [`Transaction`] into a [`TxInfo`].
    ///
    /// Strips every field not needed by the guest (individual compliance and
    /// logic proof bytes, delta witness) while preserving `aggregation_proof`
    /// for the host to register as an assumption.
    ///
    /// Returns an error if `tx.delta_proof` is still a witness, or if the
    /// transaction is missing its aggregation proof.
    pub fn from_transaction(tx: &Transaction) -> Result<Self, crate::ArmError> {
        let actions = tx
            .actions
            .iter()
            .map(|action| {
                let compliance_instances = action
                    .compliance_units
                    .iter()
                    .map(|cu| cu.instance.clone())
                    .collect();
                let logic_verifier_inputs = action
                    .logic_verifier_inputs
                    .iter()
                    .map(|lvi| LogicVerifierInfo {
                        tag: lvi.tag,
                        verifying_key: lvi.verifying_key,
                        app_data: lvi.app_data.clone(),
                    })
                    .collect();
                ActionInfo {
                    compliance_instances,
                    logic_verifier_inputs,
                }
            })
            .collect();

        let delta_proof = match &tx.delta_proof {
            Delta::Proof(proof) => proof.0.to_vec(),
            Delta::Witness(_) => return Err(crate::ArmError::ExpectedDeltaProof),
        };

        let aggregation_proof = tx
            .aggregation_proof
            .clone()
            .ok_or(crate::ArmError::MissingField("aggregation_proof"))?;

        Ok(TxInfo {
            actions,
            delta_proof,
            aggregation_proof,
        })
    }
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
    /// The transactions to execute and verify, in compact [`TxInfo`] form.
    pub transactions: Vec<TxInfo>,
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
