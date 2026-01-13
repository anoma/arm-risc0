//! Transaction structure and associated methods.

use crate::{
    action::Action,
    delta_proof::{DeltaInstance, DeltaProof, DeltaWitness},
    error::ArmError,
};
use serde::{Deserialize, Serialize};

/// Represents a transaction consisting of actions, delta proof, expected balance,
/// and optional aggregation proof.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Transaction {
    /// The actions included in the transaction.
    pub actions: Vec<Action>,
    /// The delta proof, which can be either a witness for proving or a proof for verification.
    pub delta_proof: Delta,
    /// We can't support unbalanced transactions, so this is just a placeholder.
    pub expected_balance: Option<Vec<u8>>,
    /// The aggregation proof, if present, attesting to the validity of all individual proofs.
    pub aggregation_proof: Option<Vec<u8>>,
}

/// Represents either a delta witness for proving or a delta proof for verification.
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
            actions,
            delta_proof: delta,
            expected_balance: None,
            aggregation_proof: None,
        }
    }

    /// Generates the delta proof for the transaction if it contains a delta witness.
    pub fn generate_delta_proof(self) -> Result<Transaction, ArmError> {
        match self.delta_proof {
            Delta::Witness(ref witness) => {
                let msg = self.get_delta_msg()?;
                let proof = DeltaProof::prove(&msg, witness)?;
                let delta_proof = Delta::Proof(proof);
                Ok(Transaction {
                    actions: self.actions,
                    delta_proof,
                    expected_balance: self.expected_balance,
                    aggregation_proof: self.aggregation_proof,
                })
            }
            Delta::Proof(_) => Ok(self),
        }
    }

    /// Inner check for nullifier duplication across all compliance units
    pub fn nf_duplication_check(&self) -> Result<(), ArmError> {
        let mut seen_nullifiers = std::collections::HashSet::new();
        for action in &self.actions {
            for cu in action.get_compliance_units() {
                if !seen_nullifiers.insert(cu.instance.consumed_nullifier) {
                    return Err(ArmError::NullifierDuplication);
                }
            }
        }
        Ok(())
    }

    /// Returns the DeltaInstance constructed from the sum of all actions' deltas.
    pub fn delta(&self) -> Result<DeltaInstance, ArmError> {
        let mut points = Vec::with_capacity(self.actions.len());
        for action in &self.actions {
            points.push(action.delta()?);
        }
        DeltaInstance::from_deltas(&points)
    }

    /// Constructs the delta message by concatenating the delta messages
    /// of each action.
    pub fn get_delta_msg(&self) -> Result<Vec<u8>, ArmError> {
        let mut msg = Vec::new();
        for action in &self.actions {
            msg.extend(action.get_delta_msg());
        }
        Ok(msg)
    }

    /// Composes two transactions by concatenating their actions and combining their delta witnesses.
    pub fn compose(tx1: Transaction, tx2: Transaction) -> Transaction {
        let mut actions = tx1.actions;
        actions.extend(tx2.actions);
        let delta = match (&tx1.delta_proof, &tx2.delta_proof) {
            (Delta::Witness(witness1), Delta::Witness(witness2)) => {
                Delta::Witness(witness1.compose(witness2))
            }
            _ => panic!("Cannot compose transactions with different delta types"),
        };
        Transaction::create(actions, delta)
    }
}
