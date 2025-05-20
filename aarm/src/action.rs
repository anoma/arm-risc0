use crate::{
    evm_adapter::{AdapterAction, AdapterComplianceUnit, AdapterLogicProof},
    logic_proof::LogicProof,
    utils::verify as verify_proof,
};
use aarm_core::{
    action_tree::MerkleTree, compliance::ComplianceInstance, logic_instance::LogicInstance,
};
use compliance_circuit::COMPLIANCE_GUEST_ID;
use k256::ProjectivePoint;
use risc0_ethereum_contracts::encode_seal;
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Action {
    pub compliance_units: Vec<Receipt>,
    pub logic_proofs: Vec<LogicProof>,
}

impl Action {
    pub fn new(compliance_units: Vec<Receipt>, logic_proofs: Vec<LogicProof>) -> Self {
        Action {
            compliance_units,
            logic_proofs,
        }
    }

    pub fn get_compliance_units(&self) -> &Vec<Receipt> {
        &self.compliance_units
    }

    pub fn get_logic_proofs(&self) -> &Vec<LogicProof> {
        &self.logic_proofs
    }

    pub fn verify(&self) -> bool {
        for receipt in &self.compliance_units {
            if !verify_proof(receipt, COMPLIANCE_GUEST_ID) {
                return false;
            }
        }

        let compliance_intances = self
            .compliance_units
            .iter()
            .map(|receipt| receipt.journal.decode().unwrap())
            .collect::<Vec<ComplianceInstance>>();

        // Construct the action tree
        let tags = compliance_intances
            .iter()
            .flat_map(|instance| vec![instance.nullifier, instance.commitment])
            .collect::<Vec<_>>();
        let logics = compliance_intances
            .iter()
            .flat_map(|instance| vec![instance.consumed_logic_ref, instance.created_logic_ref])
            .collect::<Vec<_>>();
        let action_tree = MerkleTree::new(tags.clone());
        let root = action_tree.root();

        for proof in &self.logic_proofs {
            let instance: LogicInstance = proof.receipt.journal.decode().unwrap();

            if root != instance.root {
                return false;
            }

            if let Some(index) = tags.iter().position(|&tag| tag == instance.tag) {
                if proof.verifying_key != logics[index] {
                    return false;
                }
            } else {
                return false;
            }

            if !verify_proof(&proof.receipt, proof.verifying_key) {
                return false;
            }
        }

        true
    }

    pub fn get_delta(&self) -> Vec<ProjectivePoint> {
        self.compliance_units
            .iter()
            .map(|receipt| {
                let instance: ComplianceInstance = receipt.journal.decode().unwrap();
                instance.delta_projective()
            })
            .collect()
    }

    pub fn get_delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        for receipt in &self.compliance_units {
            let instance: ComplianceInstance = receipt.journal.decode().unwrap();
            msg.extend_from_slice(&instance.delta_msg());
        }
        msg
    }

    pub fn convert(&self) -> AdapterAction {
        let compliance_units = self
            .compliance_units
            .iter()
            .map(|receipt| AdapterComplianceUnit {
                proof: encode_seal(&receipt).unwrap(),
                instance: receipt.journal.decode().unwrap(),
            })
            .collect();

        let logic_proofs = self
            .logic_proofs
            .iter()
            .map(|proof| AdapterLogicProof {
                verifying_key: proof.verifying_key,
                proof: encode_seal(&proof.receipt).unwrap(),
                instance: proof.receipt.journal.decode().unwrap(),
            })
            .collect();

        AdapterAction {
            compliance_units,
            logic_proofs,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::utils::groth16_prove;
    use aarm_core::{
        compliance::ComplianceWitness, constants::COMMITMENT_TREE_DEPTH, delta_proof::DeltaWitness,
        resource_logic::TrivialLogicWitness,
    };
    use compliance_circuit::COMPLIANCE_GUEST_ELF;
    use trivial_logic::{TRIVIAL_GUEST_ELF, TRIVIAL_GUEST_ID};

    pub fn create_an_action() -> (Action, DeltaWitness) {
        let compliance_witness = ComplianceWitness::<COMMITMENT_TREE_DEPTH>::default();
        let compliance_receipt = groth16_prove(&compliance_witness, COMPLIANCE_GUEST_ELF);

        let trivial_logic = TrivialLogicWitness::default();
        let trivial_logic_receipt = groth16_prove(&trivial_logic, TRIVIAL_GUEST_ELF);
        let logic_proof = LogicProof {
            receipt: trivial_logic_receipt,
            verifying_key: TRIVIAL_GUEST_ID.into(),
        };

        let compliance_units = vec![compliance_receipt];
        let logic_proofs = vec![logic_proof];

        let action = Action::new(compliance_units, logic_proofs);
        assert!(action.verify());

        let delta_witness = DeltaWitness::from_scalars(&[compliance_witness.rcv]);
        (action, delta_witness)
    }

    #[test]
    fn test_action() {
        let _ = create_an_action();
    }
}
