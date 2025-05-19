use crate::utils::{groth16_prove, verify as verify_proof};
use aarm_core::{
    action_tree::ACTION_TREE_DEPTH, merkle_path::MerklePath, nullifier_key::NullifierKey,
    nullifier_key::NullifierKeyCommitment, resource::Resource, resource_logic::TrivialLogicWitness,
};
use rand::Rng;
use risc0_zkvm::{sha::Digest, Receipt};
use serde::{Deserialize, Serialize};
use trivial_logic::{TRIVIAL_GUEST_ELF, TRIVIAL_GUEST_ID};

pub trait LogicProver: Default + Clone + Serialize + for<'de> Deserialize<'de> {
    type Witness: Default + Clone + Serialize + for<'de> Deserialize<'de>;

    fn proving_key() -> Vec<u8>;

    fn verifying_key() -> Digest;

    fn witness(&self) -> &Self::Witness;

    fn prove(&self) -> LogicProof {
        let receipt = groth16_prove(self.witness(), &Self::proving_key());
        LogicProof {
            receipt,
            verifying_key: Self::verifying_key(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogicProof {
    // Receipt contains the proof and the public inputs
    pub receipt: Receipt,
    pub verifying_key: Digest,
}

impl LogicProof {
    pub fn verify(&self) -> bool {
        verify_proof(&self.receipt, self.verifying_key)
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PaddingResourceLogic {
    witness: TrivialLogicWitness,
}

impl LogicProver for PaddingResourceLogic {
    type Witness = TrivialLogicWitness;

    fn proving_key() -> Vec<u8> {
        TRIVIAL_GUEST_ELF.to_vec()
    }

    fn verifying_key() -> Digest {
        TRIVIAL_GUEST_ID.into()
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
        Resource {
            logic_ref: Self::verifying_key(),
            label_ref: Digest::default(),
            quantity: 0,
            value_ref: Digest::default(),
            is_ephemeral: true,
            nonce: rng.gen(),
            nk_commitment,
            rand_seed: rng.gen(),
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

#[test]
fn test_trivial_logic_prover() {
    let trivial_logic = PaddingResourceLogic::default();
    let proof = trivial_logic.prove();
    assert!(proof.verify());
}
