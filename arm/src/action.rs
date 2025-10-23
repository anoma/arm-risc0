use crate::{
    action_tree::MerkleTree,
    compliance::{ConsumedMemorandum, CreatedMemorandum, CI},
    compliance_unit::{CUInner, CUI},
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

impl<ComplianceUnit: CUInner> Action<ComplianceUnit> {
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

        // Construct the action tree using tags from the CUs
        let (consumed_memos, created_memos): (Vec<ConsumedMemorandum>, Vec<CreatedMemorandum>) = {
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
            let memos: (Vec<Vec<ConsumedMemorandum>>, Vec<Vec<CreatedMemorandum>>) = self
                .compliance_units
                .iter()
                .map(|cu| (cu.consumed().unwrap(), cu.created().unwrap()))
                .unzip();
            (
                memos.0.into_iter().flatten().collect(),
                memos.1.into_iter().flatten().collect(),
            )
        };
        let action_tree = Action::<ComplianceUnit>::construct_action_tree(
            &consumed_memos
                .iter()
                .map(|memo| memo.resource_nullifier)
                .collect::<Vec<_>>(),
            &created_memos
                .iter()
                .map(|memo| memo.resource_commitment)
                .collect::<Vec<_>>(),
        );
        let root = action_tree.root();

        // Match logic verifier inputs with the tags in the action tree
        if consumed_memos.len() + created_memos.len() != self.logic_verifier_inputs.len() {
            return Err(ArmError::TagNotFound);
        }
        for (tag, logic, is_consumed) in consumed_memos
            .iter()
            .map(|memo| (memo.resource_nullifier, memo.resource_logic_ref, true))
            .chain(
                created_memos
                    .iter()
                    .map(|memo| (memo.resource_commitment, memo.resource_logic_ref, false)),
            )
        {
            // Look up the tag in the `logic_verifier_inputs`.
            if let Some(input) = self
                .logic_verifier_inputs
                .iter()
                .find(|input| input.tag == tag)
            {
                if input.verifying_key != logic {
                    return Err(ArmError::VerifyingKeyMismatch);
                }
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
                msg.extend_from_slice(&instance.delta_msg());
            } else {
                return Err(ArmError::InvalidComplianceInstance);
            }
        }
        Ok(msg)
    }

    /// Computes the action tree from the passed nullifiers and commitments. A canonical
    /// ordering is settled by sorting. For consistency, should be used in both, creation
    /// and verification of the action.
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
