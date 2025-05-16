use aarm::logic_proof::LogicProver;
use aarm_core::{nullifier_key::NullifierKey, resource::Resource};
pub use denomination_core::SimpleDenominationWitness;
use denomination_logic_circuit::{DENOMINATION_ELF, DENOMINATION_ID};
use kudo_core::denomination::Denomination;
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct SimpleDenominationResourceLogic {
    witness: SimpleDenominationWitness,
}

impl LogicProver for SimpleDenominationResourceLogic {
    type Witness = SimpleDenominationWitness;

    fn proving_key() -> Vec<u8> {
        DENOMINATION_ELF.to_vec()
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
        self.witness.denomination_resource.clone()
    }

    fn nf_key(&self) -> NullifierKey {
        self.witness.denomination_nf_key.clone()
    }
}

impl From<SimpleDenominationWitness> for SimpleDenominationResourceLogic {
    fn from(witness: SimpleDenominationWitness) -> Self {
        Self { witness }
    }
}
