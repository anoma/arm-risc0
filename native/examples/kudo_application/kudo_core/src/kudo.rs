use aarm_core::{nullifier_key::NullifierKey, resource::Resource};

// This trait defines the common interface for all denomination types. The
// resource and nullifier key are to construct the compliance proof.
pub trait Kudo {
    fn resource(&self) -> Resource;
    fn nf_key(&self) -> NullifierKey;
    // TODO: add more methods
}
