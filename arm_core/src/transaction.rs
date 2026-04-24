//! Transaction structure and associated methods.

use crate::{
    action::Action,
    compliance::ComplianceInstance,
    compliance_unit::ComplianceUnit,
    delta_types::{DeltaProof, DeltaWitness},
    error::ArmError,
};
use serde::{Deserialize, Serialize};

/// Represents a transaction consisting of actions, delta proof, expected balance,
/// and optional aggregation proof.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
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
    pub fn create(actions: Vec<Action>, delta: Delta) -> Self {
        Transaction {
            actions,
            delta_proof: delta,
            expected_balance: None,
            aggregation_proof: None,
        }
    }

    /// Inner check for nullifier duplication across all compliance units
    pub fn nf_duplication_check(&self) -> Result<(), ArmError> {
        let mut seen_nullifiers = std::collections::HashSet::new();
        for action in &self.actions {
            for cu in action.get_compliance_units() {
                let instance = ComplianceInstance::from_journal(&cu.instance)?;
                if !seen_nullifiers.insert(instance.consumed_nullifier) {
                    return Err(ArmError::NullifierDuplication);
                }
            }
        }
        Ok(())
    }

    /// Constructs the delta message by concatenating the delta messages
    /// of each action. Fails if any compliance unit's journal bytes cannot
    /// be parsed as a `ComplianceInstance`.
    pub fn get_delta_msg(&self) -> Result<Vec<u8>, ArmError> {
        let mut msg = Vec::new();
        for action in &self.actions {
            msg.extend_from_slice(&action.get_delta_msg()?);
        }
        Ok(msg)
    }

    /// Returns all compliance units in the transaction.
    pub fn get_compliance_units(&self) -> Vec<&ComplianceUnit> {
        self.actions
            .iter()
            .flat_map(|a| a.get_compliance_units().iter())
            .collect()
    }

    /// Returns `true` if any compliance or resource logic proof is `None`.
    pub fn base_proofs_are_empty(&self) -> bool {
        for a in self.actions.iter() {
            if a.get_compliance_units().iter().any(|cu| cu.proof.is_none()) {
                return true;
            }
            if a.get_logic_verifier_inputs()
                .iter()
                .any(|lp| lp.proof.is_none())
            {
                return true;
            }
        }

        false
    }
}
