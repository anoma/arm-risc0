//! An action represents a set of compliance units and logic verifiers.

use crate::{
    action_tree::MerkleTree,
    compliance::ComplianceInstance,
    compliance_unit::ComplianceUnit,
    error::ArmError,
    logic_proof::{LogicVerifier, LogicVerifierInputs},
};
use k256::ProjectivePoint;
use risc0_zkp::core::digest::Digest;
use serde::{Deserialize, Serialize};

/// An action consists of compliance units and logic verifier inputs.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Action {
    /// The compliance units in this action.
    pub compliance_units: Vec<ComplianceUnit>,
    /// The logic verifier inputs in this action.
    pub logic_verifier_inputs: Vec<LogicVerifierInputs>,
}

impl Action {
    /// Creates a new Action from compliance units and logic verifiers.
    pub fn new(
        compliance_units: Vec<ComplianceUnit>,
        logic_verifiers: Vec<LogicVerifier>,
    ) -> Result<Self, ArmError> {
        let logic_verifier_inputs: Vec<LogicVerifierInputs> = logic_verifiers
            .into_iter()
            .map(|lv| lv.try_into())
            .collect::<Result<_, _>>()?;
        Ok(Action {
            compliance_units,
            logic_verifier_inputs,
        })
    }

    /// Returns a reference to the compliance units.
    pub fn get_compliance_units(&self) -> &Vec<ComplianceUnit> {
        &self.compliance_units
    }

    /// Returns a reference to the logic verifier inputs.
    pub fn get_logic_verifier_inputs(&self) -> &Vec<LogicVerifierInputs> {
        &self.logic_verifier_inputs
    }

    /// Constructs logic verifiers from the action's compliance units and logic verifier inputs.
    /// It also checks consistency between compliance instances and logic verifier inputs.
    #[cfg(feature = "zkvm")]
    pub(crate) fn get_logic_verifiers(&self) -> Result<Vec<LogicVerifier>, ArmError> {
        let mut logic_verifiers = Vec::new();

        let compliance_intances: Vec<ComplianceInstance> = self
            .compliance_units
            .iter()
            .map(|unit| unit.instance.clone())
            .collect();

        // Construct the action tree
        let tags: Vec<Digest> = compliance_intances
            .iter()
            .flat_map(|instance| vec![instance.consumed_nullifier, instance.created_commitment])
            .collect();
        let logics = compliance_intances
            .iter()
            .flat_map(|instance| vec![instance.consumed_logic_ref, instance.created_logic_ref])
            .collect::<Vec<_>>();
        let action_tree = MerkleTree::from(tags.clone());
        let root = action_tree.root()?;

        // Match logic verifier inputs with the tags in the action tree
        if tags.len() != self.logic_verifier_inputs.len() {
            return Err(ArmError::TagNotFound);
        }

        for (index, (tag, logic)) in tags.iter().zip(logics.iter()).enumerate() {
            // Look up the tag in the `logic_verifier_inputs`.
            if let Some(input) = self
                .logic_verifier_inputs
                .iter()
                .find(|input| &input.tag == tag)
            {
                if input.verifying_key != *logic {
                    return Err(ArmError::VerifyingKeyMismatch);
                }

                let is_consumed = index % 2 == 0;
                let verifier = input.clone().to_logic_verifier(is_consumed, root)?;
                logic_verifiers.push(verifier);
            } else {
                return Err(ArmError::TagNotFound);
            }
        }

        Ok(logic_verifiers)
    }

    /// Verifies all proofs and consistencies in the action.
    #[cfg(feature = "zkvm")]
    pub fn verify(self) -> Result<(), ArmError> {
        for unit in &self.compliance_units {
            unit.verify()?;
        }

        let logic_verifiers = self.get_logic_verifiers()?;
        for verifier in logic_verifiers.iter() {
            verifier.verify()?;
        }

        Ok(())
    }

    /// This function computes the delta of the action by summing up the deltas
    /// of each compliance unit.
    pub fn delta(&self) -> Result<ProjectivePoint, ArmError> {
        self.compliance_units
            .iter()
            .try_fold(ProjectivePoint::IDENTITY, |acc, unit| {
                Ok(acc + unit.delta()?)
            })
    }

    /// Constructs the delta message by concatenating the delta messages
    /// of each compliance unit.
    pub fn get_delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        for unit in &self.compliance_units {
            msg.extend_from_slice(&unit.instance.delta_msg());
        }
        msg
    }
}

#[cfg(feature = "zkvm")]
impl Action {
    /// Constructs logic verifiers from the action's compliance units and logic verifier inputs.
    /// It also checks consistency between compliance instances and logic verifier inputs.
    pub(crate) fn get_logic_verifiers(&self) -> Result<Vec<LogicVerifier>, ArmError> {
        let mut logic_verifiers = Vec::new();

        let compliance_intances: Vec<ComplianceInstance> = self
            .compliance_units
            .iter()
            .map(|unit| unit.instance.clone())
            .collect();

        // Construct the action tree
        let tags: Vec<Digest> = compliance_intances
            .iter()
            .flat_map(|instance| vec![instance.consumed_nullifier, instance.created_commitment])
            .collect();
        let logics = compliance_intances
            .iter()
            .flat_map(|instance| vec![instance.consumed_logic_ref, instance.created_logic_ref])
            .collect::<Vec<_>>();
        let action_tree = MerkleTree::from(tags.clone());
        let root = action_tree.root()?;

        // Match logic verifier inputs with the tags in the action tree
        if tags.len() != self.logic_verifier_inputs.len() {
            return Err(ArmError::TagNotFound);
        }

        for (index, (tag, logic)) in tags.iter().zip(logics.iter()).enumerate() {
            // Look up the tag in the `logic_verifier_inputs`.
            if let Some(input) = self
                .logic_verifier_inputs
                .iter()
                .find(|input| &input.tag == tag)
            {
                if input.verifying_key != *logic {
                    return Err(ArmError::VerifyingKeyMismatch);
                }

                let is_consumed = index % 2 == 0;
                let verifier = input.clone().to_logic_verifier(is_consumed, root)?;
                logic_verifiers.push(verifier);
            } else {
                return Err(ArmError::TagNotFound);
            }
        }

        Ok(logic_verifiers)
    }

    /// Verifies all proofs and consistencies in the action.
    pub fn verify(self) -> Result<(), ArmError> {
        for unit in &self.compliance_units {
            unit.verify()?;
        }

        let logic_verifiers = self.get_logic_verifiers()?;
        for verifier in logic_verifiers.iter() {
            verifier.verify()?;
        }

        Ok(())
    }
}
