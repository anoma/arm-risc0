pub mod increment;
pub mod init;

use arm::{
    action_tree::MerkleTree, compliance::ComplianceWitness, encryption::AffinePoint,
    merkle_path::MerklePath, nullifier_key::NullifierKey, resource::Resource,
};
use arm::{
    compliance_unit::ComplianceUnit,
    error::ArmError,
    logic_proof::{LogicProver, LogicVerifier},
};
use counter_witness::CounterWitness;
use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;
use serde::{Deserialize, Serialize};

pub const SIMPLE_COUNTER_ELF: &[u8] = include_bytes!("../elf/counter-guest.bin");
lazy_static! {
    pub static ref SIMPLE_COUNTER_ID: Digest =
        Digest::from_hex("bfb58975cdb5cb0256d0e816f735bba9d7ac5a7738b5da75fa75023d6885d535")
            .unwrap();
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct CounterLogic {
    witness: CounterWitness,
}

impl CounterLogic {
    pub fn new(
        is_consumed: bool,
        old_counter: Resource,
        old_counter_existence_path: MerklePath,
        nf_key: NullifierKey,
        new_counter: Resource,
        new_counter_existence_path: MerklePath,
        discovery_pk: AffinePoint,
    ) -> Self {
        Self {
            witness: CounterWitness::new(
                is_consumed,
                old_counter,
                old_counter_existence_path,
                nf_key,
                new_counter,
                new_counter_existence_path,
                discovery_pk,
            ),
        }
    }
}

impl LogicProver for CounterLogic {
    type Witness = CounterWitness;
    fn proving_key() -> &'static [u8] {
        SIMPLE_COUNTER_ELF
    }

    fn verifying_key() -> Digest {
        *SIMPLE_COUNTER_ID
    }

    fn witness(&self) -> &Self::Witness {
        &self.witness
    }
}

pub fn convert_counter_to_value_ref(value: u128) -> Digest {
    let mut arr = [0u8; 32];
    let bytes = value.to_le_bytes();
    arr[..16].copy_from_slice(&bytes); // left-align, right-pad with 0
    Digest::from(arr)
}

pub fn generate_compliance_proof(
    consumed_counter: Resource,
    nf_key: NullifierKey,
    merkle_path: MerklePath,
    created_counter: Resource,
) -> Result<(ComplianceUnit, Vec<u8>), ArmError> {
    let compliance_witness = ComplianceWitness::from_resources_with_path(
        consumed_counter,
        nf_key,
        merkle_path,
        created_counter,
    );
    let compliance_unit = ComplianceUnit::create(&compliance_witness)?;
    Ok((compliance_unit, compliance_witness.rcv))
}

pub fn generate_logic_proofs(
    consumed_counter: Resource,
    nf_key: NullifierKey,
    consumed_discovery_pk: AffinePoint,
    created_counter: Resource,
    created_discovery_pk: AffinePoint,
) -> Result<Vec<LogicVerifier>, ArmError> {
    let consumed_counter_nf = consumed_counter.nullifier(&nf_key)?;
    let created_counter_cm = created_counter.commitment();

    let action_tree = MerkleTree::new(vec![consumed_counter_nf, created_counter_cm]);

    let consumed_counter_path = action_tree.generate_path(&consumed_counter_nf)?;
    let created_counter_path = action_tree.generate_path(&created_counter_cm)?;

    let consumed_counter_logic = CounterLogic::new(
        true,
        consumed_counter,
        consumed_counter_path.clone(),
        nf_key.clone(),
        created_counter,
        created_counter_path.clone(),
        consumed_discovery_pk,
    );
    let consumed_logic_proof = consumed_counter_logic.prove()?;

    let created_counter_logic = CounterLogic::new(
        false,
        consumed_counter,
        consumed_counter_path,
        nf_key,
        created_counter,
        created_counter_path,
        created_discovery_pk,
    );
    let created_logic_proof = created_counter_logic.prove()?;

    Ok(vec![consumed_logic_proof, created_logic_proof])
}
