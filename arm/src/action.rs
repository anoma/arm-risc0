//! An action represents a set of compliance units and logic verifiers.

pub use arm_core::action::Action;

use k256::ProjectivePoint;

use crate::{
    action_tree::MerkleTree,
    compliance_unit::{ComplianceUnit, ComplianceUnitExt},
    error::ArmError,
    logic_proof::{LogicVerifier, LogicVerifierInputsExt},
    Digest, LogicVerifierInputs,
};

/// Extension methods for actions that require zkvm/k256 functionality.
pub trait ActionExt {
    /// Creates a new Action from compliance units and logic verifiers.
    fn new(
        compliance_units: Vec<ComplianceUnit>,
        logic_verifiers: Vec<LogicVerifier>,
    ) -> Result<Self, ArmError>
    where
        Self: Sized;

    /// Verifies all proofs and consistencies in the action.
    fn verify(self) -> Result<(), ArmError>;

    /// This function computes the delta of the action by summing up the deltas
    /// of each compliance unit.
    fn delta(&self) -> Result<ProjectivePoint, ArmError>;

    /// Constructs logic verifiers from compliance units and logic verifier inputs.
    fn get_logic_verifiers(&self) -> Result<Vec<LogicVerifier>, ArmError>;
}

impl ActionExt for Action {
    fn new(
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

    fn verify(self) -> Result<(), ArmError> {
        for unit in &self.compliance_units {
            unit.verify()?;
        }

        let logic_verifiers = self.get_logic_verifiers()?;
        for verifier in &logic_verifiers {
            verifier.verify()?;
        }

        Ok(())
    }

    fn delta(&self) -> Result<ProjectivePoint, ArmError> {
        self.compliance_units
            .iter()
            .try_fold(ProjectivePoint::IDENTITY, |acc, unit| {
                Ok(acc + unit.delta()?)
            })
    }

    fn get_logic_verifiers(&self) -> Result<Vec<LogicVerifier>, ArmError> {
        let mut logic_verifiers = Vec::new();

        // Construct the action tree.
        let tags: Vec<Digest> = self
            .compliance_units
            .iter()
            .flat_map(|unit| {
                [
                    unit.instance.consumed_nullifier,
                    unit.instance.created_commitment,
                ]
            })
            .collect();
        let logics: Vec<Digest> = self
            .compliance_units
            .iter()
            .flat_map(|unit| {
                [
                    unit.instance.consumed_logic_ref,
                    unit.instance.created_logic_ref,
                ]
            })
            .collect();
        let action_tree = MerkleTree::from(tags.clone());
        let root = action_tree.root()?;

        // Match logic verifier inputs with the tags in the action tree.
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
}
