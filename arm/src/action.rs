use crate::{
    action_tree::MerkleTree,
    compliance::CI,
    compliance_unit::CUI,
    error::ArmError,
    logic_proof::{LogicVerifier, LogicVerifierInputs},
};
use k256::ProjectivePoint;
use risc0_zkvm::Digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Action<ComplianceUnit: CUI> {
    pub compliance_units: Vec<ComplianceUnit>,
    pub logic_verifier_inputs: Vec<LogicVerifierInputs>,
}

impl<ComplianceUnit: CUI> Action<ComplianceUnit> {
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

    pub fn get_compliance_units(&self) -> &Vec<ComplianceUnit> {
        &self.compliance_units
    }

    pub fn get_logic_verifier_inputs(&self) -> &Vec<LogicVerifierInputs> {
        &self.logic_verifier_inputs
    }

    pub(crate) fn get_logic_verifiers(&self) -> Result<Vec<LogicVerifier>, ArmError> {
        let mut logic_verifiers = Vec::new();

        // Get the tags from the CUs and construct the action tree
        let (nullifiers, mut commitments): (Vec<Digest>, Vec<Digest>) = {
            if let Some(bad_cu) = self
                .compliance_units
                .iter()
                .find(|cu| cu.created().is_err() || cu.consumed().is_err())
            {
                match bad_cu.created() {
                    Err(e) => return Err(e),
                    Ok(_) => return Err(bad_cu.consumed().unwrap_err()),
                }
            }
            let nfs_comms: (Vec<Vec<Digest>>, Vec<Vec<Digest>>) = self
                .compliance_units
                .iter()
                .map(|cu| (cu.consumed().unwrap(), cu.created().unwrap()))
                .unzip();
            (
                nfs_comms.0.into_iter().flatten().collect(),
                nfs_comms.1.into_iter().flatten().collect(),
            )
        };
        let action_tree =
            Action::<ComplianceUnit>::construct_action_tree(&nullifiers, &commitments);
        let root = action_tree.root();

        // Match logic verifier inputs with the tags in the action tree
        let mut tags = nullifiers.clone();
        tags.append(&mut commitments);
        if tags.len() != self.logic_verifier_inputs.len() {
            return Err(ArmError::TagNotFound);
        }
        let mut logics_in_cus = Vec::new();
        for cu in self.compliance_units.iter() {
            logics_in_cus.append(&mut cu.logic_refs()?.clone());
        }
        let mut resource_logics: Vec<Digest> = self
            .logic_verifier_inputs
            .iter()
            .map(|inp| inp.verifying_key)
            .collect();
        logics_in_cus.sort();
        resource_logics.sort();
        if logics_in_cus != resource_logics {
            return Err(ArmError::VerifyingKeyMismatch);
        }

        for input in self.logic_verifier_inputs.iter() {
            if let Some(index_in_atree) = action_tree
                .leaves
                .iter()
                .position(|leave| *leave == input.tag)
            {
                // based on the tree position
                let is_consumed = index_in_atree < nullifiers.len();
                let verifier = input.clone().to_logic_verifier(is_consumed, root)?;
                logic_verifiers.push(verifier);
            } else {
                return Err(ArmError::TagNotFound);
            }
        }

        Ok(logic_verifiers)
    }

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

    // This function computes the delta of the action by summing up the deltas
    // of each compliance unit.
    pub fn delta(&self) -> Result<ProjectivePoint, ArmError> {
        self.compliance_units
            .iter()
            .try_fold(ProjectivePoint::IDENTITY, |acc, unit| {
                Ok(acc + unit.delta()?)
            })
    }

    pub fn get_delta_msg(&self) -> Result<Vec<u8>, ArmError> {
        let mut msg = Vec::new();
        for unit in &self.compliance_units {
            if let Ok(instance) = unit.instance() {
                msg.extend_from_slice(&CI::delta_msg(&instance));
            } else {
                return Err(ArmError::InvalidComplianceInstance);
            }
        }
        Ok(msg)
    }

    /// Computes the action tree from the passed nullifiers and commitments (the leaves of the tree).
    /// For consistency, should be used in both, creation and verification of the action.
    pub fn construct_action_tree(nullifiers: &[Digest], commitments: &[Digest]) -> MerkleTree {
        let mut ordered_nfs = nullifiers.to_vec();
        ordered_nfs.sort();

        let mut ordered_comms = commitments.to_vec();
        ordered_comms.sort();

        let mut leaves = ordered_nfs;
        leaves.append(&mut ordered_comms);

        MerkleTree::new(leaves)
    }
}
