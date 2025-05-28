use aarm::logic_proof::LogicProver;
use aarm_core::{nullifier_key::NullifierKey, resource::Resource};
use kudo_core::kudo::Kudo;
pub const KUDO_LOGIC_ELF: &[u8] = include_bytes!("../../../elfs/kudo-logic.bin");
pub const KUDO_LOGIC_ID: [u32; 8] = [
    2180851034, 2718074376, 3239141689, 1351813527, 1622732300, 2436380035, 1838980537, 1125642721,
];
pub use kudo_resource_core::KudoResourceLogicWitness;
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct KudoResourceLogic {
    witness: KudoResourceLogicWitness,
}

impl LogicProver for KudoResourceLogic {
    type Witness = KudoResourceLogicWitness;

    fn proving_key() -> &'static [u8] {
        KUDO_LOGIC_ELF
    }

    fn verifying_key() -> Digest {
        KUDO_LOGIC_ID.into()
    }

    fn witness(&self) -> &Self::Witness {
        &self.witness
    }
}

impl Kudo for KudoResourceLogic {
    fn resource(&self) -> Resource {
        self.witness.kudo_resource.clone()
    }

    fn nf_key(&self) -> NullifierKey {
        self.witness.kudo_nf_key.clone()
    }
}

impl From<KudoResourceLogicWitness> for KudoResourceLogic {
    fn from(witness: KudoResourceLogicWitness) -> Self {
        Self { witness }
    }
}
