use aarm_core::{
    action_tree::ACTION_TREE_DEPTH, encryption::Ciphertext, logic_instance::LogicInstance,
    merkle_path::MerklePath, nullifier_key::NullifierKey, resource::Resource,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct ReceiveLogicWitness {
    // Receive related fields
    pub receive_resource: Resource,
    pub receive_existence_path: MerklePath<ACTION_TREE_DEPTH>,
    pub is_consumed: bool,
    pub nf_key: NullifierKey,

    // Kudo related fields
    pub kudo_resource: Resource,
    pub kudo_existence_path: MerklePath<ACTION_TREE_DEPTH>,
}

impl ReceiveLogicWitness {
    pub fn constrain(&self) -> LogicInstance {
        // Load the self resource, the receive resource is always a
        // created resource
        let self_cm = self.receive_resource.commitment();
        let tag = if self.is_consumed {
            self.receive_resource
                .nullifier_from_commitment(&self.nf_key, &self_cm)
                .unwrap()
        } else {
            self_cm
        };
        let root = self.receive_existence_path.root(tag);

        // Check basic properties of the receive resource
        assert_eq!(self.receive_resource.quantity, 0);
        assert!(self.receive_resource.is_ephemeral);

        // Load the kudo resource
        let kudo_cm = self.kudo_resource.commitment();
        let kudo_root = self.kudo_existence_path.root(kudo_cm);
        assert_eq!(root, kudo_root);

        // Check if receive_resource.label equals kudo_resource.cm to ensure the
        // target kudo is loaded.
        assert_eq!(self.receive_resource.label_ref, kudo_cm);

        // TODO: add custom receive logic

        LogicInstance {
            tag,
            is_consumed: self.is_consumed, // It can be either consumed or created to reduce padding resources
            root,
            cipher: Ciphertext::default(), // no cipher needed
            app_data: Vec::new(),          // no app data needed
        }
    }

    pub fn create_issued_persistent_witness(
        receive_resource: Resource,
        receive_existence_path: MerklePath<ACTION_TREE_DEPTH>,
        nf_key: NullifierKey,
        kudo_resource: Resource,
        kudo_existence_path: MerklePath<ACTION_TREE_DEPTH>,
    ) -> Self {
        Self {
            receive_resource,
            receive_existence_path,
            is_consumed: true,
            nf_key,
            kudo_resource,
            kudo_existence_path,
        }
    }
}
