use aarm_core::{nullifier_key::NullifierKey, resource::Resource};

// This trait defines the common interface for all receive types. The resource
// and nullifier key are to construct the compliance proof.
pub trait Receive {
    fn resource(&self) -> Resource;
    fn nf_key(&self) -> NullifierKey;
    // TODO: add more methods
}
