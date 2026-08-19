//! An action represents a compliance unit and the logic verifiers that
//! correspond to its consumed and created resources.

use crate::{compliance_unit::ComplianceUnit, logic_proof::LogicVerifierInput};
use serde::{Deserialize, Serialize};

/// A compliance unit paired with the inputs needed to verify the resource
/// logics referenced by the unit's consumed and created memorandums.
///
/// Constructing an `Action` from raw [`crate::logic_proof::LogicVerifier`]s
/// requires decoding their journals, so the constructor is a host/zkVM
/// engine operation (`anoma-rm-risc0`'s `action::new`).
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
    /// Returns a reference to the compliance unit.
    pub fn get_compliance_unit(&self) -> &ComplianceUnit {
        &self.compliance_unit
    }

    /// Returns a reference to the logic verifier inputs.
    pub fn get_logic_verifier_inputs(&self) -> &[LogicVerifierInput] {
        &self.logic_verifier_inputs
    }
}
