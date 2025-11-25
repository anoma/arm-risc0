use crate::{
    error::ArmError, logic_instance::AppData, logic_instance::LogicInstance,
    nullifier_key::NullifierKey, resource::Resource,
};
use risc0_zkvm::Digest;
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
    fn constrain(&self) -> Result<LogicInstance, ArmError>;
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Anoma.Arm.TrivialLogicWitness")]
pub struct TrivialLogicWitness {
    pub resource: Resource,
    pub action_tree_root: Digest,
    pub is_consumed: bool,
    pub nf_key: NullifierKey,
}

impl LogicCircuit for TrivialLogicWitness {
    fn constrain(&self) -> Result<LogicInstance, ArmError> {
        // Load the self resource
        let tag = self.resource.tag(self.is_consumed, &self.nf_key)?;

        // The trivial resource is ephemeral and has zero quantity
        assert_eq!(self.resource.quantity, 0);
        assert!(self.resource.is_ephemeral);

        Ok(LogicInstance {
            tag,
            is_consumed: self.is_consumed, // It can be either consumed or created to reduce padding resources
            root: self.action_tree_root,
            app_data: AppData::default(), // No app data for trivial logic
        })
    }
}

impl TrivialLogicWitness {
    pub fn new(
        resource: Resource,
        action_tree_root: Digest,
        nf_key: NullifierKey,
        is_consumed: bool,
    ) -> Self {
        Self {
            resource,
            action_tree_root,
            is_consumed,
            nf_key,
        }
    }
}
