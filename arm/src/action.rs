use crate::{
    action_tree::MerkleTree,
    compliance::ComplianceInstance,
    compliance_unit::ComplianceUnit,
    logic_proof::{LogicVerifier, LogicVerifierInputs},
};
#[cfg(feature = "prove")]
use crate::{
    compliance::ComplianceWitness, delta_proof::DeltaWitness, logic_proof::LogicProver,
    nullifier_key::NullifierKey, resource::Resource,
};

use k256::ProjectivePoint;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Action {
    pub compliance_units: Vec<ComplianceUnit>,
    pub logic_verifier_inputs: Vec<LogicVerifierInputs>,
}

impl Action {
    pub fn new(compliance_units: Vec<ComplianceUnit>, logic_verifiers: Vec<LogicVerifier>) -> Self {
        Action {
            compliance_units,
            logic_verifier_inputs: logic_verifiers.into_iter().map(|lv| lv.into()).collect(),
        }
    }

    pub fn get_compliance_units(&self) -> &Vec<ComplianceUnit> {
        &self.compliance_units
    }

    pub fn get_logic_verifier_inputs(&self) -> &Vec<LogicVerifierInputs> {
        &self.logic_verifier_inputs
    }

    pub fn verify(self) -> bool {
        for unit in &self.compliance_units {
            if !unit.verify() {
                return false;
            }
        }

        let compliance_intances = self
            .compliance_units
            .iter()
            .map(|unit| unit.get_instance())
            .collect::<Vec<ComplianceInstance>>();

        // Construct the action tree
        let tags: Vec<Vec<u32>> = compliance_intances
            .iter()
            .flat_map(|instance| {
                vec![
                    instance.consumed_nullifier.clone(),
                    instance.created_commitment.clone(),
                ]
            })
            .collect();
        let logics = compliance_intances
            .iter()
            .flat_map(|instance| {
                vec![
                    instance.consumed_logic_ref.clone(),
                    instance.created_logic_ref.clone(),
                ]
            })
            .collect::<Vec<_>>();
        let action_tree = MerkleTree::from(tags.clone());
        let root = action_tree.root();

        for input in self.logic_verifier_inputs {
            if let Some(index) = tags.iter().position(|tag| *tag == input.tag) {
                if input.verifying_key != logics[index] {
                    // The verifying_key doesn't match the resource logic
                    return false;
                }

                let is_comsumed = index % 2 == 0;
                let verifier = input.to_logic_verifier(is_comsumed, root.clone());
                if !verifier.verify() {
                    return false;
                }
            } else {
                // Tag not found
                return false;
            }
        }

        true
    }

    // This function computes the delta of the action by summing up the deltas
    // of each compliance unit.
    pub fn delta(&self) -> ProjectivePoint {
        self.compliance_units
            .iter()
            .fold(ProjectivePoint::IDENTITY, |acc, unit| acc + unit.delta())
    }

    pub fn get_delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        for unit in &self.compliance_units {
            let instance = unit.get_instance();
            msg.extend_from_slice(&instance.delta_msg());
        }
        msg
    }
}

#[cfg(feature = "prove")]
pub fn create_an_action(nonce: u8) -> (Action, DeltaWitness) {
    use crate::logic_proof::TestLogic;

    let nf_key = NullifierKey::default();
    let nf_key_cm = nf_key.commit();
    let mut consumed_resource = Resource {
        logic_ref: TestLogic::verifying_key_as_bytes(),
        nk_commitment: nf_key_cm,
        quantity: 1,
        ..Default::default()
    };
    consumed_resource.nonce[0] = nonce;
    let consumed_resource_nf = consumed_resource.nullifier(&nf_key).unwrap();

    let mut created_resource = consumed_resource.clone();
    created_resource.set_nonce(consumed_resource_nf.as_bytes().to_vec());

    let compliance_witness = ComplianceWitness::with_fixed_rcv(
        consumed_resource.clone(),
        nf_key.clone(),
        created_resource.clone(),
    );
    let compliance_receipt = ComplianceUnit::create(&compliance_witness);

    let created_resource_cm = created_resource.commitment();
    let action_tree = MerkleTree::new(vec![consumed_resource_nf, created_resource_cm]);
    let consumed_resource_path = action_tree.generate_path(&consumed_resource_nf).unwrap();
    let created_resource_path = action_tree.generate_path(&created_resource_cm).unwrap();

    let consumed_logic = TestLogic::new(
        consumed_resource,
        consumed_resource_path,
        nf_key.clone(),
        true,
    );
    let consumed_logic_proof = consumed_logic.prove();

    let created_logic = TestLogic::new(created_resource, created_resource_path, nf_key, false);
    let created_logic_proof = created_logic.prove();

    let compliance_units = vec![compliance_receipt];
    let logic_verifier_inputs = vec![consumed_logic_proof, created_logic_proof];

    let action = Action::new(compliance_units, logic_verifier_inputs);
    assert!(action.clone().verify());

    let delta_witness = DeltaWitness::from_bytes_vec(&[compliance_witness.rcv]);
    (action, delta_witness)
}

#[cfg(feature = "prove")]
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
