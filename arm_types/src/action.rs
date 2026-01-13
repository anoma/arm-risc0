//! An action represents a set of compliance units and logic verifiers.

use crate::{compliance_unit::ComplianceUnit, error::ArmError, logic_proof::LogicVerifierInputs};
use k256::ProjectivePoint;
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
    /// Returns a reference to the compliance units.
    pub fn get_compliance_units(&self) -> &Vec<ComplianceUnit> {
        &self.compliance_units
    }

    /// Returns a reference to the logic verifier inputs.
    pub fn get_logic_verifier_inputs(&self) -> &Vec<LogicVerifierInputs> {
        &self.logic_verifier_inputs
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
