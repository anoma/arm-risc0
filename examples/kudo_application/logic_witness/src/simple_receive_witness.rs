pub use arm::resource_logic::LogicCircuit;
use arm::{
    logic_instance::{AppData, LogicInstance},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SimpleReceiveLogicWitness {
    // Receive related fields
    pub receive_resource: Resource,
    pub receive_existence_path: MerklePath,
    pub is_consumed: bool,
    pub nf_key: NullifierKey,

    // Kudo related fields
    pub kudo_resource: Resource,
    pub kudo_existence_path: MerklePath,
}

impl LogicCircuit for SimpleReceiveLogicWitness {
    fn constrain(&self) -> LogicInstance {
        // Load the self resource, the receive resource is always a
        // created resource
        let tag = self.receive_resource.tag(self.is_consumed, &self.nf_key);
        let root = self.receive_existence_path.root(&tag);

        // Check basic properties of the receive resource
        assert_eq!(self.receive_resource.quantity, 0);
        assert!(self.receive_resource.is_ephemeral);

        // Load the kudo resource
        let kudo_cm = self.kudo_resource.commitment();
        let kudo_root = self.kudo_existence_path.root(&kudo_cm);
        assert_eq!(root, kudo_root);

        // Check if receive_resource.label equals kudo_resource.cm to ensure the
        // target kudo is loaded.
        assert_eq!(self.receive_resource.label_ref, kudo_cm.as_bytes());

        // TODO: add custom receive logic

        LogicInstance {
            tag: tag.as_words().to_vec(),
            is_consumed: self.is_consumed, // It can be either consumed or created to reduce padding resources
            root,
            app_data: AppData::default(), // no app data needed
        }
    }
}

impl SimpleReceiveLogicWitness {
    pub fn generate_witness(
        receive_resource: Resource,
        receive_existence_path: MerklePath,
        nf_key: NullifierKey,
        is_consumed: bool,
        kudo_resource: Resource,
        kudo_existence_path: MerklePath,
    ) -> Self {
        Self {
            receive_resource,
            receive_existence_path,
            is_consumed,
            nf_key,
            kudo_resource,
            kudo_existence_path,
        }
    }
}
