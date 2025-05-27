use crate::utils::groth16_prove;
use crate::{
    constants::{COMPLIANCE_GUEST_ELF, COMPLIANCE_GUEST_ID, TEST_GUEST_ELF, TEST_GUEST_ID},
    logic_proof::LogicProof,
    utils::verify as verify_proof,
};
use aarm_core::compliance::ComplianceWitness;
use aarm_core::delta_proof::DeltaWitness;
use aarm_core::nullifier_key::NullifierKey;
use aarm_core::resource::Resource;
use aarm_core::resource_logic::TrivialLogicWitness;
use aarm_core::{
    action_tree::MerkleTree, compliance::ComplianceInstance, constants::COMMITMENT_TREE_DEPTH,
    logic_instance::LogicInstance,
};
use k256::ProjectivePoint;
use risc0_zkvm::{Digest, Receipt};
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
            .flat_map(|instance| vec![instance.consumed_nullifier, instance.created_commitment])
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
}

pub fn create_an_action(nonce: u8) -> (Action, DeltaWitness) {
    let nf_key = NullifierKey::new(Digest::default());
    let nf_key_cm = nf_key.commit();
    let mut consumed_resource = Resource::default();
    consumed_resource.logic_ref = Digest::new(TEST_GUEST_ID.into());
    consumed_resource.nk_commitment = nf_key_cm;
    consumed_resource.nonce[0] = nonce;
    let mut created_resource = consumed_resource.clone();
    created_resource.nonce[10] = nonce;

    let compliance_witness = ComplianceWitness::<COMMITMENT_TREE_DEPTH>::with_fixed_rcv(
        consumed_resource,
        nf_key,
        created_resource,
    );
    let compliance_receipt = groth16_prove(&compliance_witness, &COMPLIANCE_GUEST_ELF);

    let consumed_resource_nf = consumed_resource.nullifier(&nf_key).unwrap();
    let created_resource_cm = created_resource.commitment();
    let action_tree = MerkleTree::new(vec![consumed_resource_nf, created_resource_cm]);
    let consumed_resource_path = action_tree.generate_path(consumed_resource_nf).unwrap();
    let created_resource_path = action_tree.generate_path(created_resource_cm).unwrap();

    let consumed_logic_witness =
        TrivialLogicWitness::new(consumed_resource, consumed_resource_path, nf_key, true);
    let consumed_logic_receipt = groth16_prove(&consumed_logic_witness, &TEST_GUEST_ELF);
    let consumed_logic_proof = LogicProof {
        receipt: consumed_logic_receipt,
        verifying_key: TEST_GUEST_ID.into(),
    };

    let created_logic_witness =
        TrivialLogicWitness::new(created_resource, created_resource_path, nf_key, false);
    let created_logic_receipt = groth16_prove(&created_logic_witness, &TEST_GUEST_ELF);
    let created_logic_proof = LogicProof {
        receipt: created_logic_receipt,
        verifying_key: TEST_GUEST_ID.into(),
    };

    let compliance_units = vec![compliance_receipt];
    let logic_proofs = vec![consumed_logic_proof, created_logic_proof];

    let action = Action::new(compliance_units, logic_proofs);
    assert!(action.verify());

    let delta_witness = DeltaWitness::from_scalars(&[compliance_witness.rcv]);
    (action, delta_witness)
}

pub fn create_multiple_actions(n: usize) -> (Vec<Action>, DeltaWitness) {
    let mut actions = Vec::new();
    let mut delta_witnesses = Vec::new();
    for i in 0..n {
        let (action, delta_witness) = create_an_action(i as u8);
        actions.push(action);
        delta_witnesses.push(delta_witness);
    }
    (actions, DeltaWitness::compress(&delta_witnesses))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_action() {
        let _ = create_an_action(1);
    }
}
