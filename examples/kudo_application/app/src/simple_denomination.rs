use arm::logic_proof::LogicProver;
use arm::{
    merkle_path::MerklePath, merkle_path::COMMITMENT_TREE_DEPTH, nullifier_key::NullifierKey,
    resource::Resource,
};
use hex::FromHex;
use kudo_logic_witness::simple_denomination_witness::SimpleDenominationLogicWitness;
use kudo_traits::{compliance_info::ComplianceWitnessInfo, resource_info::DenominationInfo};
use lazy_static::lazy_static;
use risc0_zkvm::Digest;
use serde::{Deserialize, Serialize};

pub const DENOMINATION_ELF: &[u8] = include_bytes!("../elfs/simple-kudo-denomination-guest.bin");
lazy_static! {
    pub static ref DENOMINATION_ID: Digest =
        Digest::from_hex("a923f5e478393d85d754617bb53756d8c54a2c60a83da0fc59475eebe8cab81a")
            .unwrap();
}

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

    fn verifying_key() -> Digest {
        *DENOMINATION_ID
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
