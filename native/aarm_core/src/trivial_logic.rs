use crate::{
    action_tree::ACTION_TREE_DEPTH,
    constants::TRIVIAL_RESOURCE_LOGIC,
    encryption::Ciphertext,
    logic_instance::LogicInstance,
    merkle_path::MerklePath,
    nullifier_key::{NullifierKey, NullifierKeyCommitment},
    resource::Resource,
};
use rand::Rng;
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct TrivialLogicWitness {
    pub resource: Resource,
    pub receive_existence_path: MerklePath<ACTION_TREE_DEPTH>,
    pub is_consumed: bool,
    pub nf_key: NullifierKey,
}

impl TrivialLogicWitness {
    pub fn constrain(&self) -> LogicInstance {
        // Load the self resource, the receive resource is always a
        // created resource
        let self_cm = self.resource.commitment();
        let tag = if self.is_consumed {
            self.resource
                .nullifier_from_commitment(&self.nf_key, &self_cm)
                .unwrap()
        } else {
            self_cm
        };
        let root = self.receive_existence_path.root(tag);

        // Check basic properties of the receive resource
        assert_eq!(self.resource.quantity, 0);
        assert!(self.resource.is_ephemeral);

        LogicInstance {
            tag,
            is_consumed: self.is_consumed, // It can be either consumed or created to reduce padding resources
            root,
            cipher: Ciphertext::default(), // no cipher needed
            app_data: Vec::new(),          // no app data needed
        }
    }

    pub fn create_trivial_resource(nk_commitment: NullifierKeyCommitment) -> Resource {
        let mut rng = rand::thread_rng();
        Resource {
            logic_ref: TRIVIAL_RESOURCE_LOGIC.into(),
            label_ref: Digest::default(),
            quantity: 0,
            value_ref: Digest::default(),
            is_ephemeral: true,
            nonce: rng.gen(),
            nk_commitment,
            rand_seed: rng.gen(),
        }
    }

    pub fn create_witness(
        resource: Resource,
        receive_existence_path: MerklePath<ACTION_TREE_DEPTH>,
        nf_key: NullifierKey,
        is_consumed: bool,
    ) -> Self {
        Self {
            resource,
            receive_existence_path,
            is_consumed,
            nf_key,
        }
    }
}

impl Default for TrivialLogicWitness {
    fn default() -> Self {
        let mut witness = TrivialLogicWitness {
            resource: Resource::default(),
            receive_existence_path: MerklePath::default(),
            is_consumed: false,
            nf_key: NullifierKey::default(),
        };

        let mut rng = rand::thread_rng();
        witness.resource.is_ephemeral = true;
        witness.resource.quantity = 0;
        witness.resource.nonce = rng.gen();
        witness.resource.logic_ref = TRIVIAL_RESOURCE_LOGIC.into();
        witness
    }
}
