use arm::logic_proof::LogicProver;
use arm::{merkle_path::MerklePath, nullifier_key::NullifierKey, resource::Resource};
use hex::FromHex;
use kudo_logic_witness::simple_denomination_witness::SimpleDenominationLogicWitness;
use kudo_traits::{compliance_info::ComplianceWitnessInfo, resource_info::DenominationInfo};
use lazy_static::lazy_static;
use risc0_zkvm::Digest;
use serde::{Deserialize, Serialize};

pub const DENOMINATION_ELF: &[u8] = include_bytes!("../elfs/simple-kudo-denomination-guest.bin");
lazy_static! {
    pub static ref DENOMINATION_ID: Digest =
        Digest::from_hex("375ed92ddeb0cd61b107c53ff07afd8b2c1653febeca31fb0e5898084e080789")
            .unwrap();
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct SimpleDenominationInfo {
    logic_witness: SimpleDenominationLogicWitness,
    merkle_path: Option<MerklePath>,
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

    fn merkle_path(&self) -> Option<MerklePath> {
        self.merkle_path.clone()
    }
}

impl DenominationInfo for SimpleDenominationInfo {}

impl SimpleDenominationInfo {
    pub fn new(
        logic_witness: SimpleDenominationLogicWitness,
        merkle_path: Option<MerklePath>,
    ) -> Self {
        Self {
            logic_witness,
            merkle_path,
        }
    }
}
