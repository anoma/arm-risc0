use crate::{
    evm_adapter::{AdapterAction, AdapterComplianceUnit, AdapterLogicProof},
    logic_proof::LogicProof,
    utils::verify as verify_proof,
};
use aarm_core::compliance::ComplianceInstance;
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

        for proof in &self.logic_proofs {
            if !verify_proof(&proof.receipt, proof.verifying_key) {
                return false;
            }
        }

        // TODO: Verify other checks
        // Actually, the verification should occur on validators/EVM adapter.

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
                seal: encode_seal(&receipt).unwrap(),
                journal: receipt.journal.bytes.clone(),
            })
            .collect();

        let logic_proofs = self
            .logic_proofs
            .iter()
            .map(|proof| AdapterLogicProof {
                verifying_key: proof.verifying_key.as_bytes().to_vec(),
                seal: encode_seal(&proof.receipt).unwrap(),
                journal: proof.receipt.journal.bytes.clone(),
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
    };
    use compliance_circuit::{COMPLIANCE_GUEST_ELF, COMPLIANCE_GUEST_ID};

    pub fn create_an_action() -> (Action, DeltaWitness) {
        let compliance_witness = ComplianceWitness::<COMMITMENT_TREE_DEPTH>::default();

        let receipt = groth16_prove(&compliance_witness, COMPLIANCE_GUEST_ELF);
        let logic_proof = LogicProof {
            receipt: receipt.clone(),
            verifying_key: COMPLIANCE_GUEST_ID.into(),
        };

        let compliance_units = vec![receipt.clone()];
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
