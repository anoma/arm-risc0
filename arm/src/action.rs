//! Host/zkVM engine operations on [`Action`]: construction from raw logic
//! verifiers, proof verification, and delta computation. The `Action` type
//! itself lives in `anoma-rm-core` and is re-exported here unchanged.

pub use arm_core::action::*;

use crate::{
    action_tree::ActionTree,
    compliance_unit::ComplianceUnit,
    error::ArmError,
    logic_proof::{LogicVerifier, LogicVerifierInput},
};
use k256::ProjectivePoint;
use risc0_zkvm::Digest;

/// Builds an `Action` from a compliance unit and the matching set of logic verifiers.
pub fn new(
    compliance_unit: ComplianceUnit,
    logic_verifiers: Vec<LogicVerifier>,
) -> Result<Action, ArmError> {
    let logic_verifier_inputs: Vec<LogicVerifierInput> = logic_verifiers
        .into_iter()
        .map(crate::logic_proof::to_verifier_input)
        .collect::<Result<_, _>>()?;
    Ok(Action {
        compliance_unit,
        logic_verifier_inputs,
    })
}

/// Constructs logic verifiers from the action's compliance unit and logic verifier inputs.
///
/// Uses positional matching: `logic_verifier_inputs` must be supplied in
/// the canonical tag order (consumed nullifiers then created commitments),
/// which is the same order `ComplianceInstance::tags()` produces and the
/// aggregation guest enforces.
pub(crate) fn get_logic_verifiers(action: &Action) -> Result<Vec<LogicVerifier>, ArmError> {
    let compliance_instance = crate::compliance_unit::get_instance(&action.compliance_unit)?;

    let tags: Vec<Digest> = compliance_instance.tags().collect();

    if tags.len() != action.logic_verifier_inputs.len() {
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
        .zip(action.logic_verifier_inputs.iter())
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
            crate::logic_proof::input_to_logic_verifier(
                input.clone(),
                is_consumed,
                action_tree_root,
            )
        })
        .collect()
}

/// Verifies all proofs and consistencies in the action.
pub fn verify(action: &Action) -> Result<(), ArmError> {
    crate::compliance_unit::verify(&action.compliance_unit)?;

    let logic_verifiers = get_logic_verifiers(action)?;
    for verifier in logic_verifiers.iter() {
        crate::logic_proof::verify(verifier)?;
    }

    Ok(())
}

/// This function computes the delta of the action by summing up the deltas
/// of each compliance unit.
pub fn delta(action: &Action) -> Result<ProjectivePoint, ArmError> {
    crate::compliance_unit::delta(&action.compliance_unit)
}

/// Returns this action's contribution to the delta message: its action tree root.
pub fn get_delta_msg(action: &Action) -> Result<Vec<u8>, ArmError> {
    let instance = crate::compliance_unit::get_instance(&action.compliance_unit)
        .map_err(|_| ArmError::InvalidComplianceInstance)?;
    let tags: Vec<Digest> = instance.tags().collect();
    let root = ActionTree::new(tags).root()?;
    Ok(root.as_bytes().to_vec())
}
