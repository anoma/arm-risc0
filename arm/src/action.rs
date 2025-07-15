use crate::{
    action_tree::MerkleTree,
    compliance::{ComplianceInstance, ComplianceWitness},
    compliance_unit::ComplianceUnit,
    delta_proof::DeltaWitness,
    logic_proof::{LogicProof, LogicProver},
    merkle_path::Leaf,
    merkle_path::COMMITMENT_TREE_DEPTH,
    nullifier_key::NullifierKey,
    resource::Resource,
    resource_logic::TrivialLogicWitness,
};
use k256::ProjectivePoint;
#[cfg(feature = "nif")]
use rustler::{types::map::map_new, Atom, Decoder, Encoder, Env, NifResult, Term};
use serde::{Deserialize, Serialize};

#[cfg(feature = "nif")]
use rustler::NifStruct;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Anoma.Arm.Action")]
pub struct Action {
    pub compliance_units: Vec<ComplianceUnit>,
    pub logic_verifier_inputs: Vec<LogicProof>,
    pub resource_forwarder_calldata_pairs: Vec<(Resource, ForwarderCalldata)>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForwarderCalldata {
    pub untrusted_forwarder: [u8; 20],
    pub input: Vec<u8>,
    pub output: Vec<u8>,
}

#[cfg(feature = "nif")]
impl Encoder for ForwarderCalldata {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let map = map_new(env);
        // store the name of the elixir struct
        let map = map
            .map_put(
                Atom::from_str(env, "__struct__").unwrap(),
                Atom::from_str(env, "Elixir.Anoma.Arm.ForwarderCalldata").unwrap(),
            )
            .unwrap();

        map
    }
}

#[cfg(feature = "nif")]
impl<'a> Decoder<'a> for ForwarderCalldata {
    fn decode(_term: Term<'a>) -> NifResult<Self> {
        Ok(ForwarderCalldata {
            untrusted_forwarder: [0u8; 20],
            input: vec![],
            output: vec![],
        })
    }
}

impl Action {
    pub fn new(
        compliance_units: Vec<ComplianceUnit>,
        logic_verifier_inputs: Vec<LogicProof>,
        resource_forwarder_calldata_pairs: Vec<(Resource, ForwarderCalldata)>,
    ) -> Self {
        Action {
            compliance_units,
            logic_verifier_inputs,
            resource_forwarder_calldata_pairs,
        }
    }

    pub fn get_compliance_units(&self) -> &Vec<ComplianceUnit> {
        &self.compliance_units
    }

    pub fn get_logic_verifier_inputs(&self) -> &Vec<LogicProof> {
        &self.logic_verifier_inputs
    }

    pub fn get_resource_forwarder_calldata_pairs(&self) -> &Vec<(Resource, ForwarderCalldata)> {
        &self.resource_forwarder_calldata_pairs
    }

    pub fn verify(&self) -> bool {
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
        let tags = compliance_intances
            .iter()
            .flat_map(|instance| {
                vec![
                    instance.consumed_nullifier.clone().into(),
                    instance.created_commitment.clone().into(),
                ]
            })
            .collect::<Vec<Leaf>>();
        let logics = compliance_intances
            .iter()
            .flat_map(|instance| {
                vec![
                    instance.consumed_logic_ref.clone(),
                    instance.created_logic_ref.clone(),
                ]
            })
            .collect::<Vec<_>>();
        let action_tree = MerkleTree::new(tags.clone());
        let root = action_tree.root();

        for proof in &self.logic_verifier_inputs {
            let instance = proof.get_instance();

            if root != instance.root {
                return false;
            }

            let instance_tag: Leaf = instance.tag.clone().into();
            if let Some(index) = tags.iter().position(|tag| tag == &instance_tag) {
                if proof.verifying_key != logics[index] {
                    return false;
                }
            } else {
                return false;
            }

            if !proof.verify() {
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

pub fn create_an_action(nonce: u8) -> (Action, DeltaWitness) {
    let nf_key = NullifierKey::default();
    let nf_key_cm = nf_key.commit();
    let mut consumed_resource = Resource {
        logic_ref: TrivialLogicWitness::verifying_key_as_bytes(),
        nk_commitment: nf_key_cm,
        ..Default::default()
    };
    consumed_resource.nonce[0] = nonce;
    let consumed_resource_nf = consumed_resource.nullifier(&nf_key).unwrap();

    let mut created_resource = consumed_resource.clone();
    created_resource.set_nonce(consumed_resource_nf.clone());

    let compliance_witness = ComplianceWitness::<COMMITMENT_TREE_DEPTH>::with_fixed_rcv(
        consumed_resource.clone(),
        nf_key.clone(),
        created_resource.clone(),
    );
    let compliance_receipt = ComplianceUnit::create(&compliance_witness);

    let created_resource_cm = created_resource.commitment();
    let action_tree = MerkleTree::new(vec![
        consumed_resource_nf.clone().into(),
        created_resource_cm.clone().into(),
    ]);
    let consumed_resource_path = action_tree.generate_path(&consumed_resource_nf).unwrap();
    let created_resource_path = action_tree.generate_path(&created_resource_cm).unwrap();

    let consumed_logic_witness = TrivialLogicWitness::new(
        consumed_resource,
        consumed_resource_path,
        nf_key.clone(),
        true,
    );
    let consumed_logic_proof = consumed_logic_witness.prove();

    let created_logic_witness =
        TrivialLogicWitness::new(created_resource, created_resource_path, nf_key, false);
    let created_logic_proof = created_logic_witness.prove();

    let compliance_units = vec![compliance_receipt];
    let logic_verifier_inputs = vec![consumed_logic_proof, created_logic_proof];
    let resource_forwarder_calldata_pairs = vec![];

    let action = Action::new(
        compliance_units,
        logic_verifier_inputs,
        resource_forwarder_calldata_pairs,
    );
    assert!(action.verify());

    let delta_witness = DeltaWitness::from_bytes_vec(&[compliance_witness.rcv]);
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
