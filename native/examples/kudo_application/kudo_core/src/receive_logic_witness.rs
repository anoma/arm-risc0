use aarm_core::{
    action_tree::ACTION_TREE_DEPTH, encryption::Ciphertext, logic_instance::LogicInstance,
    merkle_path::MerklePath, resource::Resource,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct ReceiveLogicWitness {
    // Receive related fields
    pub receive_resource: Resource,
    pub receive_existence_path: MerklePath<ACTION_TREE_DEPTH>,

    // Kudo related fields
    pub kudo_resource: Resource,
    pub kudo_existence_path: MerklePath<ACTION_TREE_DEPTH>,
}

impl ReceiveLogicWitness {
    pub fn constrain(&self) -> LogicInstance {
        // Load the self resource, the receive resource is always a
        // created resource
        let tag = self.receive_resource.commitment();
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
            is_consumed: false, // receive resources are always created
            root,
            cipher: Ciphertext::default(), // no cipher needed
            app_data: Vec::new(),          // no app data needed
        }
    }
}
