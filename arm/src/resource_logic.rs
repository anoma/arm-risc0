//! Logic circuit trait and trivial logic implementation.

use crate::{
    error::ArmError, logic_instance::AppData, logic_instance::LogicInstance,
    nullifier_key::NullifierKey, resource::Resource,
};
use risc0_zkp::core::digest::Digest;
use serde::{Deserialize, Serialize};

/// Trait for logic circuits, defining the necessary methods.
pub trait LogicCircuit: Default + Clone + Serialize + for<'de> Deserialize<'de> {
    /// In general, it's implemented as `Self::default()`
    fn default_witness() -> Self {
        Self::default()
    }

    /// Logic constraints implementation
    fn constrain(&self) -> Result<LogicInstance, ArmError>;
}

/// Trivial logic witness for resources that do not require complex logic proofs.
/// It's used for padding resources.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TrivialLogicWitness {
    /// The resource associated with the trivial logic.
    pub resource: Resource,
    /// The action tree root associated with the resource.
    pub action_tree_root: Digest,
    /// Indicates whether the resource is consumed.
    pub is_consumed: bool,
    /// The nullifier key associated with the resource.
    pub nf_key: NullifierKey,
}

impl LogicCircuit for TrivialLogicWitness {
    /// Logic constraints for trivial logic
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
    /// Creates a new TrivialLogicWitness with the given parameters.
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
