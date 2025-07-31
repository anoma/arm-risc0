use arm::{
    merkle_path::MerklePath, merkle_path::COMMITMENT_TREE_DEPTH, nullifier_key::NullifierKey,
    resource::Resource,
};

pub trait ComplianceWitnessInfo {
    fn resource(&self) -> Resource;
    fn nf_key(&self) -> Option<NullifierKey>;
    fn merkle_path(&self) -> Option<MerklePath<COMMITMENT_TREE_DEPTH>>;
}
