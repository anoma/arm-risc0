//! An action represents a set of compliance units and logic verifiers.

use crate::{compliance_unit::ComplianceUnit, logic_instance::LogicVerifierInputs};
use serde::{Deserialize, Serialize};

/// An action consists of compliance units and logic verifier inputs.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Action {
    /// The compliance units in this action.
    pub compliance_units: Vec<ComplianceUnit>,
    /// The logic verifier inputs in this action.
    pub logic_verifier_inputs: Vec<LogicVerifierInputs>,
}

impl Action {
    /// Returns a reference to the compliance units.
    pub fn get_compliance_units(&self) -> &Vec<ComplianceUnit> {
        &self.compliance_units
    }

    /// Returns a reference to the logic verifier inputs.
    pub fn get_logic_verifier_inputs(&self) -> &Vec<LogicVerifierInputs> {
        &self.logic_verifier_inputs
    }

    /// Constructs the delta message by concatenating the delta messages
    /// of each compliance unit.
    pub fn get_delta_msg(&self) -> Vec<u8> {
        self.compliance_units
            .iter()
            .flat_map(|unit| unit.instance.delta_msg())
            .collect()
    }
}
