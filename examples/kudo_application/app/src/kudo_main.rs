use arm::logic_proof::LogicProver;
use arm::{merkle_path::MerklePath, nullifier_key::NullifierKey, resource::Resource};
use hex::FromHex;
use kudo_logic_witness::kudo_main_witness::KudoMainWitness;
use kudo_traits::{compliance_info::ComplianceWitnessInfo, resource_info::KudoInfo};
use lazy_static::lazy_static;
use risc0_zkvm::Digest;
use serde::{Deserialize, Serialize};

pub const KUDO_LOGIC_ELF: &[u8] = include_bytes!("../elfs/kudo-main-guest.bin");
lazy_static! {
    pub static ref KUDO_LOGIC_ID: Digest =
        Digest::from_hex("8c432fa859b4d7af710f0e8e4dffffb37dfa0b6ea92766240c7aaca77b89f5ff")
            .unwrap();
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct KudoMainInfo {
    logic_witness: KudoMainWitness,
    merkle_path: Option<MerklePath>,
}

impl LogicProver for KudoMainInfo {
    type Witness = KudoMainWitness;

    fn proving_key() -> &'static [u8] {
        KUDO_LOGIC_ELF
    }

    fn verifying_key() -> Digest {
        *KUDO_LOGIC_ID
    }

    fn witness(&self) -> &Self::Witness {
        &self.logic_witness
    }
}

impl ComplianceWitnessInfo for KudoMainInfo {
    fn resource(&self) -> Resource {
        self.logic_witness.kudo_resource
    }

    fn nf_key(&self) -> Option<NullifierKey> {
        Some(self.logic_witness.kudo_nf_key.clone())
    }

    fn merkle_path(&self) -> Option<MerklePath> {
        self.merkle_path.clone()
    }
}

impl KudoInfo for KudoMainInfo {}

impl KudoMainInfo {
    pub fn new(logic_witness: KudoMainWitness, merkle_path: Option<MerklePath>) -> Self {
        Self {
            logic_witness,
            merkle_path,
        }
    }
}
