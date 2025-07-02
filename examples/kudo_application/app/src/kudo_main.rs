use arm::logic_proof::LogicProver;
use arm_core::{
    constants::COMMITMENT_TREE_DEPTH, merkle_path::MerklePath, nullifier_key::NullifierKey,
    resource::Resource,
};
use kudo_logic_witness::kudo_main_witness::KudoMainWitness;
use kudo_traits::{compliance_info::ComplianceWitnessInfo, resource_info::KudoInfo};
use serde::{Deserialize, Serialize};

pub const KUDO_LOGIC_ELF: &[u8] = include_bytes!("../../kudo_logic/elfs/kudo-main.bin");
pub const KUDO_LOGIC_ID: &[u8] = &[
    250, 57, 201, 1, 136, 161, 188, 217, 64, 220, 29, 176, 123, 150, 131, 101, 82, 3, 198, 218,
    161, 178, 19, 124, 77, 131, 32, 71, 192, 234, 174, 27,
];

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct KudoMainInfo {
    logic_witness: KudoMainWitness,
    merkle_path: Option<MerklePath<COMMITMENT_TREE_DEPTH>>,
}

impl LogicProver for KudoMainInfo {
    type Witness = KudoMainWitness;

    fn proving_key() -> &'static [u8] {
        KUDO_LOGIC_ELF
    }

    fn verifying_key() -> Vec<u8> {
        KUDO_LOGIC_ID.to_vec()
    }

    fn witness(&self) -> &Self::Witness {
        &self.logic_witness
    }
}

impl ComplianceWitnessInfo for KudoMainInfo {
    fn resource(&self) -> Resource {
        self.logic_witness.kudo_resource.clone()
    }

    fn nf_key(&self) -> Option<NullifierKey> {
        Some(self.logic_witness.kudo_nf_key.clone())
    }

    fn merkle_path(&self) -> Option<MerklePath<COMMITMENT_TREE_DEPTH>> {
        self.merkle_path.clone()
    }
}

impl KudoInfo for KudoMainInfo {}

impl KudoMainInfo {
    pub fn new(
        logic_witness: KudoMainWitness,
        merkle_path: Option<MerklePath<COMMITMENT_TREE_DEPTH>>,
    ) -> Self {
        Self {
            logic_witness,
            merkle_path,
        }
    }
}
