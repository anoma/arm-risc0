//! An action represents a compliance unit and the logic verifiers that
//! correspond to its consumed and created resources.

#[cfg(feature = "transaction")]
use crate::{action_tree::ActionTree, error::ArmError, logic_proof::LogicVerifier};
use crate::{compliance_unit::ComplianceUnit, logic_proof::LogicVerifierInput};
#[cfg(feature = "transaction")]
use k256::ProjectivePoint;
#[cfg(feature = "transaction")]
use risc0_zkp::core::digest::Digest;
use serde::{Deserialize, Serialize};

/// A compliance unit paired with the inputs needed to verify the resource
/// logics referenced by the unit's consumed and created memorandums.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Action {
    /// The compliance unit constraining the consumed and created resources.
    pub compliance_unit: ComplianceUnit,
    /// One logic-verifier input per tag (consumed nullifier or created commitment) in the unit.
    pub logic_verifier_inputs: Vec<LogicVerifierInput>,
}

impl Action {
    /// Builds an `Action` from a compliance unit and the matching set of logic verifiers.
    #[cfg(feature = "transaction")]
    pub fn new(
        compliance_unit: ComplianceUnit,
        logic_verifiers: Vec<LogicVerifier>,
    ) -> Result<Self, ArmError> {
        let logic_verifier_inputs: Vec<LogicVerifierInput> = logic_verifiers
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
    pub fn get_logic_verifier_inputs(&self) -> &[LogicVerifierInput] {
        &self.logic_verifier_inputs
    }

    /// Constructs logic verifiers from the action's compliance unit and logic verifier inputs.
    ///
    /// Uses positional matching: `logic_verifier_inputs` must be supplied in
    /// the canonical tag order (consumed nullifiers then created commitments),
    /// which is the same order `ComplianceInstance::tags()` produces and the
    /// aggregation guest enforces.
    #[cfg(feature = "transaction")]
    pub(crate) fn get_logic_verifiers(&self) -> Result<Vec<LogicVerifier>, ArmError> {
        let compliance_instance = self.compliance_unit.get_instance()?;

        let tags: Vec<Digest> = compliance_instance.tags().collect();

        if tags.len() != self.logic_verifier_inputs.len() {
            return Err(ArmError::TagNotFound);
        }

        let action_tree_root = ActionTree::new(tags).root()?;

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

        entries
            .zip(self.logic_verifier_inputs.iter())
            .map(|((tag, resource_logic_ref, is_consumed), input)| {
                // Positional tag assertion — catches wrong ordering or missing instances.
                if input.tag != tag {
                    return Err(ArmError::TagNotFound);
                }
                // The proof must be for the logic circuit the resource itself declares;
                // otherwise a proof for an unrelated (e.g. trivially-passing) circuit
                // could be substituted for the resource's real logic.
                if input.verifying_key != resource_logic_ref {
                    return Err(ArmError::VerifyingKeyMismatch);
                }
                input
                    .clone()
                    .to_logic_verifier(is_consumed, action_tree_root)
            })
            .collect()
    }

    /// Verifies all proofs and consistencies in the action.
    #[cfg(feature = "transaction")]
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
    #[cfg(feature = "transaction")]
    pub fn delta(&self) -> Result<ProjectivePoint, ArmError> {
        self.compliance_unit.delta()
    }

    /// Returns this action's contribution to the delta message: its action tree root.
    #[cfg(feature = "transaction")]
    pub fn get_delta_msg(&self) -> Result<Vec<u8>, ArmError> {
        let instance = self
            .compliance_unit
            .get_instance()
            .map_err(|_| ArmError::InvalidComplianceInstance)?;
        let tags: Vec<Digest> = instance.tags().collect();
        let root = ActionTree::new(tags).root()?;
        Ok(root.as_bytes().to_vec())
    }
}
