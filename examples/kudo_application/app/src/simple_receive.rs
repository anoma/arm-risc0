use aarm::logic_proof::LogicProver;
use aarm_core::{
    constants::COMMITMENT_TREE_DEPTH, merkle_path::MerklePath, nullifier_key::NullifierKey,
    resource::Resource,
};
use kudo_logic_witness::simple_receive_witness::SimpleReceiveLogicWitness;
use kudo_traits::{compliance_info::ComplianceWitnessInfo, resource_info::ReceiveInfo};
use serde::{Deserialize, Serialize};

pub const RECEIVE_ELF: &[u8] = include_bytes!("../../kudo_logic/elfs/simple-receive.bin");
pub const RECEIVE_ID: &[u8] = &[
    163, 90, 122, 135, 118, 170, 8, 224, 253, 97, 158, 242, 49, 251, 3, 96, 234, 174, 170, 170, 57,
    119, 91, 72, 209, 240, 28, 131, 144, 23, 68, 103,
];

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct SimpleReceiveInfo {
    logic_witness: SimpleReceiveLogicWitness,
    merkle_path: Option<MerklePath<COMMITMENT_TREE_DEPTH>>,
}

impl LogicProver for SimpleReceiveInfo {
    type Witness = SimpleReceiveLogicWitness;

    fn proving_key() -> &'static [u8] {
        RECEIVE_ELF
    }

    fn verifying_key() -> Vec<u8> {
        RECEIVE_ID.to_vec()
    }

    fn witness(&self) -> &Self::Witness {
        &self.logic_witness
    }
}

impl ComplianceWitnessInfo for SimpleReceiveInfo {
    fn resource(&self) -> Resource {
        self.logic_witness.receive_resource.clone()
    }

    fn nf_key(&self) -> Option<NullifierKey> {
        Some(self.logic_witness.nf_key.clone())
    }

    fn merkle_path(&self) -> Option<MerklePath<COMMITMENT_TREE_DEPTH>> {
        self.merkle_path.clone()
    }
}

impl ReceiveInfo for SimpleReceiveInfo {}

impl SimpleReceiveInfo {
    pub fn new(
        logic_witness: SimpleReceiveLogicWitness,
        merkle_path: Option<MerklePath<COMMITMENT_TREE_DEPTH>>,
    ) -> Self {
        Self {
            logic_witness,
            merkle_path,
        }
    }
}
