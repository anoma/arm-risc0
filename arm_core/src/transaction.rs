//! Transaction wire types and their pure structural checks.
//!
//! Everything requiring a cryptographic engine or a zkVM — delta proving
//! and verification, aggregation, receipt handling, journal decoding —
//! lives in the host/zkVM engine crate (`anoma-rm-risc0`'s `transaction`
//! module) as free functions over these types.

use crate::{
    action::Action,
    aggregation_instance::AggregationInstance,
    compliance_unit::ComplianceUnit,
    delta_proof::{DeltaProof, DeltaWitness},
    error::ArmError,
};
use serde::{Deserialize, Serialize};

/// Aggregation proof and its decoded instance — always populated together.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Aggregation {
    /// Serialised `InnerReceipt` from the aggregation prover.
    pub proof: Vec<u8>,
    /// Typed journal decoded from the receipt — the canonical public output.
    pub instance: AggregationInstance,
}

/// Represents a transaction consisting of actions, delta proof, expected balance,
/// and optional aggregation proof.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Transaction {
    /// The actions included in the transaction.
    /// `Some` before aggregation; `None` once aggregation succeeds.
    pub actions: Option<Vec<Action>>,
    /// The delta proof, which can be either a witness for proving or a proof for verification.
    pub delta_proof: Delta,
    /// We can't support unbalanced transactions, so this is just a placeholder.
    pub expected_balance: Option<Vec<u8>>,
    /// Present after aggregation succeeds; `None` before aggregation.
    pub aggregation: Option<Aggregation>,
}

/// Represents either a delta witness for proving or a delta proof for verification.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Delta {
    /// The delta witness used for proving the delta proof.
    Witness(DeltaWitness),
    /// The delta proof used for verification.
    Proof(DeltaProof),
}

impl Transaction {
    /// Create a new transaction with the given actions and delta.
    /// Delta proof is a deterministic process, no proving key is needed.
    /// Delta instance can be constructed from the actions.
    pub fn create(actions: Vec<Action>, delta: Delta) -> Self {
        Transaction {
            actions: Some(actions),
            delta_proof: delta,
            expected_balance: None,
            aggregation: None,
        }
    }

    /// Ensures exactly one of `actions` / `aggregation` is populated.
    ///
    /// A `Transaction` is a plain deserializable struct, so nothing besides
    /// this check stops a crafted instance from carrying both fields at
    /// once. Callers must not derive authenticated data (delta, nullifiers)
    /// from a transaction that fails this check.
    pub fn check_representation(&self) -> Result<(), ArmError> {
        match (&self.actions, &self.aggregation) {
            (Some(_), None) | (None, Some(_)) => Ok(()),
            (Some(_), Some(_)) => Err(ArmError::AmbiguousTransactionRepresentation),
            (None, None) => Err(ArmError::MissingActions),
        }
    }

    /// Returns `true` if the transaction has no base proofs (i.e. it has already
    /// been aggregated and `actions` was cleared).
    pub fn base_proofs_are_empty(&self) -> bool {
        self.actions.is_none()
    }

    /// Returns all compliance units in the transaction.
    pub fn get_compliance_units(&self) -> Vec<&ComplianceUnit> {
        self.actions
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|a| &a.compliance_unit)
            .collect()
    }
}
