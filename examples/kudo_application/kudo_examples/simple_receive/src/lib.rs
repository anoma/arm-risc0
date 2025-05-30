use aarm::logic_proof::LogicProver;
use aarm_core::{nullifier_key::NullifierKey, resource::Resource};
use kudo_core::receive::Receive;
pub use receive_core::SimpleReceiveWitness;
pub const RECEIVE_ELF: &[u8] = include_bytes!("../../../elfs/receive.bin");
pub const RECEIVE_ID: [u32; 8] = [
    3310211775, 589008629, 4235198033, 3102914864, 1797110209, 280090754, 4131591913, 700179597,
];
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct SimpleReceiveLogic {
    witness: SimpleReceiveWitness,
}

impl LogicProver for SimpleReceiveLogic {
    type Witness = SimpleReceiveWitness;

    fn proving_key() -> &'static [u8] {
        RECEIVE_ELF
    }

    fn verifying_key() -> Digest {
        RECEIVE_ID.into()
    }

    fn witness(&self) -> &Self::Witness {
        &self.witness
    }
}

impl Receive for SimpleReceiveLogic {
    fn resource(&self) -> Resource {
        self.witness.receive_resource
    }

    fn nf_key(&self) -> NullifierKey {
        self.witness.nf_key
    }
}

impl From<SimpleReceiveWitness> for SimpleReceiveLogic {
    fn from(witness: SimpleReceiveWitness) -> Self {
        Self { witness }
    }
}
