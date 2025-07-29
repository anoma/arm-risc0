use crate::{
    constants::{PADDING_LOGIC_PK, PADDING_LOGIC_VK},
    proving_system::{journal_to_instance, prove, verify as verify_proof},
};
use arm_core::{
    action_tree::ACTION_TREE_DEPTH, logic_instance::LogicInstance, merkle_path::MerklePath,
    nullifier_key::NullifierKey, nullifier_key::NullifierKeyCommitment, resource::Resource,
    resource_logic::TrivialLogicWitness,
};
use rand::Rng;
#[cfg(feature = "nif")]
use rustler::NifStruct;
use serde::{Deserialize, Serialize};

pub trait LogicProver: Default + Clone + Serialize + for<'de> Deserialize<'de> {
    type Witness: Default + Clone + Serialize + for<'de> Deserialize<'de>;

    fn proving_key() -> &'static [u8];

    fn verifying_key() -> Vec<u8>;

    fn witness(&self) -> &Self::Witness;

    fn prove(&self) -> LogicProof {
        let (proof, instance) = prove(Self::proving_key(), self.witness());
        LogicProof {
            // TODO: handle the unwrap properly
            proof,
            instance,
            verifying_key: Self::verifying_key(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Anoma.Arm.LogicProof")]
pub struct LogicProof {
    pub proof: Vec<u8>,
    pub instance: Vec<u8>,
    pub verifying_key: Vec<u8>,
}

impl LogicProof {
    pub fn verify(&self) -> bool {
        verify_proof(&self.verifying_key, &self.instance, &self.proof)
    }

    pub fn get_instance(&self) -> LogicInstance {
        journal_to_instance(&self.instance)
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PaddingResourceLogic {
    witness: TrivialLogicWitness,
}

impl LogicProver for PaddingResourceLogic {
    type Witness = TrivialLogicWitness;

    fn proving_key() -> &'static [u8] {
        PADDING_LOGIC_PK
    }

    fn verifying_key() -> Vec<u8> {
        PADDING_LOGIC_VK.into()
    }

    fn witness(&self) -> &Self::Witness {
        &self.witness
    }
}

impl PaddingResourceLogic {
    pub fn new(
        resource: Resource,
        receive_existence_path: MerklePath<ACTION_TREE_DEPTH>,
        nf_key: NullifierKey,
        is_consumed: bool,
    ) -> Self {
        let witness = TrivialLogicWitness {
            resource,
            receive_existence_path,
            is_consumed,
            nf_key,
        };
        PaddingResourceLogic { witness }
    }
    pub fn create_padding_resource(nk_commitment: NullifierKeyCommitment) -> Resource {
        let mut rng = rand::thread_rng();
        let nonce: [u8; 32] = rng.gen();
        let rand_seed: [u8; 32] = rng.gen();
        Resource {
            logic_ref: Self::verifying_key(),
            label_ref: vec![0; 32],
            quantity: 0,
            value_ref: vec![0; 32],
            is_ephemeral: true,
            nonce: nonce.to_vec(),
            nk_commitment,
            rand_seed: rand_seed.to_vec(),
        }
    }
}

impl Default for PaddingResourceLogic {
    fn default() -> Self {
        let (nf_key, nk_commitment) = NullifierKey::random_pair();
        let resource = Self::create_padding_resource(nk_commitment);
        let witness = TrivialLogicWitness {
            resource,
            receive_existence_path: MerklePath::default(),
            is_consumed: false,
            nf_key,
        };
        PaddingResourceLogic { witness }
    }
}

impl LogicProver for TrivialLogicWitness {
    type Witness = TrivialLogicWitness;

    fn proving_key() -> &'static [u8] {
        PADDING_LOGIC_PK
    }

    fn verifying_key() -> Vec<u8> {
        PADDING_LOGIC_VK.into()
    }

    fn witness(&self) -> &Self::Witness {
        self
    }
}

#[test]
fn test_trivial_logic_prover() {
    let trivial_logic = PaddingResourceLogic::default();
    let proof = trivial_logic.prove();
    assert!(proof.verify());
}
