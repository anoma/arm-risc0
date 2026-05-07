//! An action represents a compliance unit and the logic verifiers that
//! correspond to its consumed and created resources.

use crate::{
    action_tree::MerkleTree,
    compliance_unit::ComplianceUnit,
    error::ArmError,
    logic_proof::{LogicVerifier, LogicVerifierInputs},
};
use k256::ProjectivePoint;
use risc0_zkvm::Digest;
use serde::{Deserialize, Serialize};

/// A compliance unit paired with the inputs needed to verify the resource
/// logics referenced by the unit's consumed and created memorandums.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Action {
    /// The compliance unit constraining the consumed and created resources.
    pub compliance_unit: ComplianceUnit,
    /// One logic-verifier input per tag (consumed nullifier or created commitment) in the unit.
    pub logic_verifier_inputs: Vec<LogicVerifierInputs>,
}

impl Action {
    /// Builds an `Action` from a compliance unit and the matching set of logic verifiers.
    pub fn new(
        compliance_unit: ComplianceUnit,
        logic_verifiers: Vec<LogicVerifier>,
    ) -> Result<Self, ArmError> {
        let logic_verifier_inputs: Vec<LogicVerifierInputs> = logic_verifiers
            .into_iter()
            .map(|lv| lv.try_into())
            .collect::<Result<_, _>>()?;
        Ok(Action {
            compliance_unit,
            logic_verifier_inputs,
        })
    }

    /// Returns a reference to the compliance unit.
    pub fn get_compliance_unit(&self) -> &ComplianceUnit {
        &self.compliance_unit
    }

    /// Returns a reference to the logic verifier inputs.
    pub fn get_logic_verifier_inputs(&self) -> &Vec<LogicVerifierInputs> {
        &self.logic_verifier_inputs
    }

    /// Constructs logic verifiers from the action's compliance unit and logic verifier inputs.
    /// It also checks consistency between compliance instances and logic verifier inputs.
    pub(crate) fn get_logic_verifiers(&self) -> Result<Vec<LogicVerifier>, ArmError> {
        let mut logic_verifiers = Vec::new();

        let compliance_instance = self.compliance_unit.get_instance()?;

        // Compute the action tree root over the unit's canonical tag order.
        let tags: Vec<Digest> = compliance_instance.tags().collect();
        let action_tree_root = Self::construct_action_tree(&tags).root()?;

        // Match logic verifier inputs with the tags in the action tree
        if tags.len() != self.logic_verifier_inputs.len() {
            return Err(ArmError::TagNotFound);
        }
        let entries = compliance_instance
            .consumed_publics
            .iter()
            .map(|r| (r.resource_nullifier, r.resource_logic_ref, true))
            .chain(
                compliance_instance
                    .created_publics
                    .iter()
                    .map(|r| (r.resource_commitment, r.resource_logic_ref, false)),
            );
        for (tag, verifying_key, is_consumed) in entries {
            // Look up the tag in the `logic_verifier_inputs`.
            let input = self
                .logic_verifier_inputs
                .iter()
                .find(|input| input.tag == tag)
                .ok_or(ArmError::TagNotFound)?;
            if input.verifying_key != verifying_key {
                return Err(ArmError::VerifyingKeyMismatch);
            }
            logic_verifiers.push(
                input
                    .clone()
                    .to_logic_verifier(is_consumed, action_tree_root)?,
            );
        }

        Ok(logic_verifiers)
    }

    /// Verifies all proofs and consistencies in the action.
    pub fn verify(&self) -> Result<(), ArmError> {
        self.compliance_unit.verify()?;

        let logic_verifiers = self.get_logic_verifiers()?;
        for verifier in logic_verifiers.iter() {
            verifier.verify()?;
        }

        Ok(())
    }

    /// This function computes the delta of the action by summing up the deltas
    /// of each compliance unit.
    pub fn delta(&self) -> Result<ProjectivePoint, ArmError> {
        self.compliance_unit.delta()
    }

    /// Constructs the delta message by concatenating the delta messages
    /// of each compliance unit.
    pub fn get_delta_msg(&self) -> Result<Vec<u8>, ArmError> {
        let mut msg = Vec::new();
        if let Ok(instance) = self.compliance_unit.get_instance() {
            msg.extend_from_slice(&instance.delta_msg());
        } else {
            return Err(ArmError::InvalidComplianceInstance);
        }
        Ok(msg)
    }

    /// Constructs the action tree from the passed tags.
    ///
    /// The caller MUST pass tags in the canonical order produced by
    /// [`ComplianceInstance::tags`] — consumed nullifiers first, then created
    /// commitments. Any other ordering (e.g. sorting) will produce a different
    /// root and the resulting action's logic proofs will fail to verify with
    /// a generic proof-verification error.
    pub fn construct_action_tree(tags: &[Digest]) -> MerkleTree {
        MerkleTree::new(tags.to_vec())
    }
}
