use crate::{
    logic_instance::AppData, logic_instance::LogicInstance, merkle_path::MerklePath,
    nullifier_key::NullifierKey, resource::Resource,
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "nif")]
use rustler::NifStruct;

/// This is a trait for logic constraints implementation.
pub trait LogicCircuit: Default + Clone + Serialize + for<'de> Deserialize<'de> {
    // In general, it's implemented as `Self::default()`
    fn default_witness() -> Self {
        Self::default()
    }

    // Logic constraints implementation
    fn constrain(&self) -> LogicInstance;
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Anoma.Arm.TrivialLogicWitness")]
pub struct TrivialLogicWitness {
    pub resource: Resource,
    pub receive_existence_path: MerklePath,
    pub is_consumed: bool,
    pub nf_key: NullifierKey,
}

impl LogicCircuit for TrivialLogicWitness {
    fn constrain(&self) -> LogicInstance {
        // Load the self resource
        let tag = self.resource.tag(self.is_consumed, &self.nf_key);
        let root = self.receive_existence_path.root(&tag);

        // The trivial resource is ephemeral and has zero quantity
        assert_eq!(self.resource.quantity, 0);
        assert!(self.resource.is_ephemeral);

        LogicInstance {
            tag: tag.as_words().to_vec(),
            is_consumed: self.is_consumed, // It can be either consumed or created to reduce padding resources
            root,
            app_data: AppData::default(), // No app data for trivial logic
        }
    }
}

impl TrivialLogicWitness {
    pub fn new(
        resource: Resource,
        receive_existence_path: MerklePath,
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
