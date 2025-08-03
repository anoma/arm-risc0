use arm::logic_proof::LogicProver;
use arm::{
    merkle_path::MerklePath, merkle_path::COMMITMENT_TREE_DEPTH, nullifier_key::NullifierKey,
    resource::Resource,
};
use hex::FromHex;
use kudo_logic_witness::simple_receive_witness::SimpleReceiveLogicWitness;
use kudo_traits::{compliance_info::ComplianceWitnessInfo, resource_info::ReceiveInfo};
use lazy_static::lazy_static;
use risc0_zkvm::Digest;
use serde::{Deserialize, Serialize};

pub const RECEIVE_ELF: &[u8] = include_bytes!("../elfs/simple-kudo-receive-guest.bin");
lazy_static! {
    pub static ref RECEIVE_ID: Digest =
        Digest::from_hex("be04cd889e4a6dfe19c82ca4025a203b4469cbcea6321639834398c8a8bca579")
            .unwrap();
}

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

    fn verifying_key() -> Digest {
        *RECEIVE_ID
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
