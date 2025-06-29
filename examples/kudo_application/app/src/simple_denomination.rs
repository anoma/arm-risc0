use aarm::logic_proof::LogicProver;
use aarm_core::{
    constants::COMMITMENT_TREE_DEPTH, merkle_path::MerklePath, nullifier_key::NullifierKey,
    resource::Resource,
};
use kudo_logic_witness::simple_denomination_witness::SimpleDenominationLogicWitness;
use kudo_traits::{compliance_info::ComplianceWitnessInfo, resource_info::DenominationInfo};
use serde::{Deserialize, Serialize};

pub const DENOMINATION_ELF: &[u8] = include_bytes!("../../kudo_logic/elfs/simple-denomination.bin");
pub const DENOMINATION_ID: &[u8] = &[
    53, 169, 201, 247, 198, 180, 57, 42, 200, 121, 112, 42, 5, 217, 114, 187, 140, 142, 217, 176,
    193, 1, 44, 141, 114, 34, 46, 167, 32, 184, 191, 73,
];

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct SimpleDenominationInfo {
    logic_witness: SimpleDenominationLogicWitness,
    merkle_path: Option<MerklePath<COMMITMENT_TREE_DEPTH>>,
}

impl LogicProver for SimpleDenominationInfo {
    type Witness = SimpleDenominationLogicWitness;

    fn proving_key() -> &'static [u8] {
        DENOMINATION_ELF
    }

    fn verifying_key() -> Vec<u8> {
        DENOMINATION_ID.to_vec()
    }

    fn witness(&self) -> &Self::Witness {
        &self.logic_witness
    }
}

impl ComplianceWitnessInfo for SimpleDenominationInfo {
    fn resource(&self) -> Resource {
        self.logic_witness.denomination_resource.clone()
    }

    fn nf_key(&self) -> Option<NullifierKey> {
        Some(self.logic_witness.denomination_nf_key.clone())
    }

    fn merkle_path(&self) -> Option<MerklePath<COMMITMENT_TREE_DEPTH>> {
        self.merkle_path.clone()
    }
}

impl DenominationInfo for SimpleDenominationInfo {}

impl SimpleDenominationInfo {
    pub fn new(
        logic_witness: SimpleDenominationLogicWitness,
        merkle_path: Option<MerklePath<COMMITMENT_TREE_DEPTH>>,
    ) -> Self {
        Self {
            logic_witness,
            merkle_path,
        }
    }
}
