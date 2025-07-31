pub mod increment;
pub mod init;

use arm::{
    action_tree::{MerkleTree, ACTION_TREE_DEPTH},
    compliance::ComplianceWitness,
    merkle_path::MerklePath,
    merkle_path::COMMITMENT_TREE_DEPTH,
    nullifier_key::NullifierKey,
    resource::Resource,
};
use arm::{
    compliance_unit::ComplianceUnit,
    logic_proof::{LogicProof, LogicProver},
};
use counter::CounterWitness;
use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;
use serde::{Deserialize, Serialize};

pub const SIMPLE_COUNTER_ELF: &[u8] = include_bytes!("../elf/simple_counter.bin");
lazy_static! {
    pub static ref SIMPLE_COUNTER_ID: Digest =
        Digest::from_hex("be068dcc59a6d0bd2fc21a945864cee6bbb13d1a0f5741999c2e77e92ecc2766")
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
        old_counter_existence_path: MerklePath<ACTION_TREE_DEPTH>,
        nf_key: NullifierKey,
        new_counter: Resource,
        new_counter_existence_path: MerklePath<ACTION_TREE_DEPTH>,
    ) -> Self {
        Self {
            witness: CounterWitness {
                is_consumed,
                old_counter,
                old_counter_existence_path,
                nf_key,
                new_counter,
                new_counter_existence_path,
            },
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

pub fn convert_counter_to_value_ref(value: u128) -> Vec<u8> {
    let mut arr = [0u8; 32];
    let bytes = value.to_le_bytes();
    arr[..16].copy_from_slice(&bytes); // left-align, right-pad with 0
    arr.to_vec()
}

pub fn generate_compliance_proof(
    consumed_counter: Resource,
    nf_key: NullifierKey,
    merkle_path: MerklePath<COMMITMENT_TREE_DEPTH>,
    created_counter: Resource,
) -> (ComplianceUnit, Vec<u8>) {
    let compliance_witness = ComplianceWitness::<COMMITMENT_TREE_DEPTH>::from_resources_with_path(
        consumed_counter,
        nf_key,
        merkle_path,
        created_counter,
    );
    let compliance_unit = ComplianceUnit::create(&compliance_witness);
    (compliance_unit, compliance_witness.rcv)
}

pub fn generate_logic_proofs(
    consumed_counter: Resource,
    nf_key: NullifierKey,
    created_counter: Resource,
) -> Vec<LogicProof> {
    let consumed_counter_nf = consumed_counter.nullifier(&nf_key).unwrap();
    let created_counter_cm = created_counter.commitment();

    let action_tree = MerkleTree::new(vec![
        consumed_counter_nf.clone().into(),
        created_counter_cm.clone().into(),
    ]);

    let consumed_counter_path = action_tree.generate_path(&consumed_counter_nf).unwrap();
    let created_counter_path = action_tree.generate_path(&created_counter_cm).unwrap();

    let consumed_counter_logic = CounterLogic::new(
        true,
        consumed_counter.clone(),
        consumed_counter_path.clone(),
        nf_key.clone(),
        created_counter.clone(),
        created_counter_path.clone(),
    );
    let consumed_logic_proof = consumed_counter_logic.prove();

    let created_counter_logic = CounterLogic::new(
        false,
        consumed_counter,
        consumed_counter_path,
        nf_key,
        created_counter,
        created_counter_path,
    );
    let created_logic_proof = created_counter_logic.prove();

    vec![consumed_logic_proof, created_logic_proof]
}
