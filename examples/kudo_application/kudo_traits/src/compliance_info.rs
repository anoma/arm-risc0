use arm::{merkle_path::MerklePath, nullifier_key::NullifierKey, resource::Resource};

pub trait ComplianceWitnessInfo {
    fn resource(&self) -> Resource;
    fn nf_key(&self) -> Option<NullifierKey>;
    fn merkle_path(&self) -> Option<MerklePath>;
}
