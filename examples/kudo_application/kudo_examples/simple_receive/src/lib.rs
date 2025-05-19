use aarm::logic_proof::LogicProver;
use aarm_core::{nullifier_key::NullifierKey, resource::Resource};
use kudo_core::receive::Receive;
pub use receive_core::SimpleReceiveWitness;
use receive_logic_circuit::{RECEIVE_ELF, RECEIVE_ID};
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct SimpleReceiveLogic {
    witness: SimpleReceiveWitness,
}

impl LogicProver for SimpleReceiveLogic {
    type Witness = SimpleReceiveWitness;

    fn proving_key() -> Vec<u8> {
        RECEIVE_ELF.to_vec()
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
        self.witness.receive_resource.clone()
    }

    fn nf_key(&self) -> NullifierKey {
        self.witness.nf_key.clone()
    }
}

impl From<SimpleReceiveWitness> for SimpleReceiveLogic {
    fn from(witness: SimpleReceiveWitness) -> Self {
        Self { witness }
    }
}
