use aarm::logic_proof::LogicProver;
use aarm_core::{nullifier_key::NullifierKey, resource::Resource};
pub use denomination_core::SimpleDenominationWitness;
pub const DENOMINATION_ELF: &[u8] = include_bytes!("../../../elfs/denomination.bin");
pub const DENOMINATION_ID: [u32; 8] = [
    752765321, 2072722720, 3155356202, 794211336, 1132666731, 942238722, 2377137829, 2293574572,
];
use kudo_core::denomination::Denomination;
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct SimpleDenominationResourceLogic {
    witness: SimpleDenominationWitness,
}

impl LogicProver for SimpleDenominationResourceLogic {
    type Witness = SimpleDenominationWitness;

    fn proving_key() -> &'static [u8] {
        DENOMINATION_ELF
    }

    fn verifying_key() -> Digest {
        DENOMINATION_ID.into()
    }

    fn witness(&self) -> &Self::Witness {
        &self.witness
    }
}

impl Denomination for SimpleDenominationResourceLogic {
    fn resource(&self) -> Resource {
        self.witness.denomination_resource
    }

    fn nf_key(&self) -> NullifierKey {
        self.witness.denomination_nf_key
    }
}

impl From<SimpleDenominationWitness> for SimpleDenominationResourceLogic {
    fn from(witness: SimpleDenominationWitness) -> Self {
        Self { witness }
    }
}
