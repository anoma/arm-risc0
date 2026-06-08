// This module contains a trivial test circuit and tx tests for the ARM crate.
// The functions here are also used in the elixir sdk and binding libraries to
// ensure that the ARM crate's transaction functionalities work as expected.

use anoma_rm_risc0::{
    action::Action,
    action_tree::MerkleTree,
    compliance::ComplianceWitness,
    compliance_unit::create_compliance_unit,
    delta_proof::DeltaWitness,
    initial_root,
    logic_proof::LogicProver,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    proving_system::ProofType,
    resource::Resource,
    transaction::{Delta, Transaction},
    ActionExt, CoreDeltaWitness, Digest, NullifierKeyExt, TransactionExt,
};
use anoma_rm_risc0_test_witness::TestLogicWitness;
use hex::FromHex;
use k256::Scalar;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

/// Keccak256 hash function matching the EVM delta proof convention.
pub fn hash_msg_keccak(msg: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    Keccak256::digest(msg).into()
}

// Test logic proving key / test logic guest ELF binary
pub const TEST_LOGIC_PK: &[u8] = include_bytes!("../elf/logic-test-guest.bin");

lazy_static! {
    // test logic verification key / compliance image id
    pub static ref TEST_LOGIC_VK: Digest =
        Digest::from_hex("6a3db06309305be76ebc3ccbccfb9984e4edc08224952726c7562949b0267612")
            .unwrap();
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct TestLogic {
    witness: TestLogicWitness,
}

impl TestLogic {
    pub fn new(
        resource: Resource,
        receive_existence_path: MerklePath,
        nf_key: NullifierKey,
        is_consumed: bool,
    ) -> Self {
        let witness = TestLogicWitness {
            resource,
            receive_existence_path,
            is_consumed,
            nf_key,
        };
        TestLogic { witness }
    }
}

impl LogicProver for TestLogic {
    type Witness = TestLogicWitness;

    fn proving_key() -> &'static [u8] {
        TEST_LOGIC_PK
    }

    fn verifying_key() -> Digest {
        *TEST_LOGIC_VK
    }

    fn witness(&self) -> &Self::Witness {
        &self.witness
    }
}

pub fn create_an_action_with_multiple_compliances(
    compliance_num: usize,
    nonce: u8,
    proof_type: ProofType,
) -> (Action, DeltaWitness) {
    let nf_key = NullifierKey::default();
    let nf_key_cm = nf_key.commit();

    // Generate multiple consumed and created resources
    let (consumed_resources, created_resources): (Vec<_>, Vec<_>) = (0..compliance_num)
        .map(|i| {
            let mut consumed_resource = Resource {
                logic_ref: TestLogic::verifying_key(),
                nk_commitment: nf_key_cm,
                quantity: 1,
                ..Default::default()
            };
            consumed_resource.nonce = [[nonce; 16], [i as u8; 16]].concat().try_into().unwrap();
            let consumed_resource_nf = consumed_resource.nullifier(&nf_key).unwrap();

            let mut created_resource = consumed_resource;
            created_resource.set_nonce(consumed_resource_nf);
            (consumed_resource, created_resource)
        })
        .unzip();

    let mut compliance_units = Vec::new();
    let mut rcvs = Vec::new();
    let mut action_tree = MerkleTree::new(vec![]);
    for i in 0..compliance_num {
        let compliance_witness = ComplianceWitness {
            consumed_resource: consumed_resources[i],
            merkle_path: MerklePath::default(), // dummy path for test
            ephemeral_root: initial_root(),
            nf_key: nf_key.clone(),
            created_resource: created_resources[i],
            rcv: Scalar::ONE.to_bytes().to_vec(), // fixed rcv for test
        };

        let compliance_receipt = create_compliance_unit(&compliance_witness, proof_type).unwrap();

        let consumed_resource_nf = consumed_resources[i].nullifier(&nf_key).unwrap();
        let created_resource_cm = created_resources[i].commitment();
        action_tree.insert(consumed_resource_nf);
        action_tree.insert(created_resource_cm);

        compliance_units.push(compliance_receipt);
        rcvs.push(compliance_witness.rcv);
    }

    let logic_verifier_inputs = (0..compliance_num)
        .flat_map(|i| {
            let consumed_resource_nf = consumed_resources[i].nullifier(&nf_key).unwrap();
            let created_resource_cm = created_resources[i].commitment();
            let consumed_resource_path = action_tree.generate_path(&consumed_resource_nf).unwrap();
            let created_resource_path = action_tree.generate_path(&created_resource_cm).unwrap();

            let consumed_logic = TestLogic::new(
                consumed_resources[i],
                consumed_resource_path,
                nf_key.clone(),
                true,
            );
            let consumed_logic_proof = consumed_logic.prove(proof_type).unwrap();

            let created_logic = TestLogic::new(
                created_resources[i],
                created_resource_path,
                nf_key.clone(),
                false,
            );
            let created_logic_proof = created_logic.prove(proof_type).unwrap();

            vec![consumed_logic_proof, created_logic_proof]
        })
        .collect();

    let action = Action::new(compliance_units, logic_verifier_inputs).unwrap();
    action.clone().verify().unwrap();

    let delta_witness = DeltaWitness::from_bytes_vec(&rcvs).unwrap();
    (action, delta_witness)
}

pub fn create_multiple_actions(
    action_num: usize,
    compliance_num: usize,
    proof_type: ProofType,
) -> (Vec<Action>, DeltaWitness) {
    let mut actions = Vec::new();
    let mut delta_witnesses = Vec::new();
    for i in 0..action_num {
        let (action, delta_witness) =
            create_an_action_with_multiple_compliances(compliance_num, i as u8, proof_type);
        actions.push(action);
        delta_witnesses.push(delta_witness);
    }
    (actions, DeltaWitness::compress(&delta_witnesses))
}

// Create a test transaction with n_actions actions, each with compliance_num compliance units
pub fn generate_test_transaction(
    n_actions: usize,
    compliance_num: usize,
    proof_type: ProofType,
) -> Transaction {
    let (actions, delta_witness) = create_multiple_actions(n_actions, compliance_num, proof_type);
    let tx = Transaction::create(
        actions,
        Delta::Witness(CoreDeltaWitness(delta_witness.to_bytes())),
    );
    let balanced_tx = tx.generate_delta_proof(hash_msg_keccak).unwrap();
    balanced_tx.clone().verify(hash_msg_keccak).unwrap();
    balanced_tx
}

#[test]
fn test_logic_prover() {
    let proof_type = ProofType::Succinct;
    let test_logic = TestLogic::default();
    let proof = test_logic.prove(proof_type).unwrap();
    proof.verify().unwrap();
}

#[test]
fn test_action() {
    let _ = create_an_action_with_multiple_compliances(2, 1, ProofType::Succinct);
}

#[test]
fn test_unmatched_logic_verifier_inputs_in_action() {
    let (actions, _) = create_multiple_actions(2, 1, ProofType::Succinct);
    // swap logic verifier inputs to cause mismatch in action0
    let mut action0 = actions[0].clone();
    action0.logic_verifier_inputs = actions[1].logic_verifier_inputs.clone();
    assert!(action0.verify().is_err());

    // empty logic verifier inputs in action1
    let mut action1 = actions[1].clone();
    action1.logic_verifier_inputs = vec![];
    assert!(action1.verify().is_err());
}

#[test]
fn test_nullifier_duplication_check() {
    let mut tx = generate_test_transaction(2, 1, ProofType::Succinct);
    assert!(tx.nf_duplication_check().is_ok());

    // Introduce a duplicate nullifier
    tx.actions[1] = tx.actions[0].clone();

    assert!(tx.nf_duplication_check().is_err());
}

#[test]
fn test_transaction() {
    let _ = generate_test_transaction(2, 2, ProofType::Succinct);
}

#[test]
#[ignore]
fn test_transaction_groth16() {
    let _ = generate_test_transaction(2, 2, ProofType::Groth16);
}

#[test]
fn test_aggregation_works() {
    let tx = generate_test_transaction(2, 2, ProofType::Succinct);
    let mut tx_str = tx.clone();
    assert!(tx_str.aggregate(ProofType::Succinct).is_ok());
    assert!(tx_str.aggregation_proof.is_some());
    assert!(tx_str.verify_aggregation().is_ok());
}

#[test]
#[ignore]
fn test_aggregation_works_groth16() {
    let tx = generate_test_transaction(2, 2, ProofType::Succinct);
    let mut tx_str = tx.clone();
    assert!(tx_str.aggregate(ProofType::Groth16).is_ok());
    assert!(tx_str.aggregation_proof.is_some());
    assert!(tx_str.verify_aggregation().is_ok());
}

#[test]
fn test_verify_aggregation_fails_for_incorrect_instances() {
    let tx = generate_test_transaction(2, 2, ProofType::Succinct);
    let mut tx_str = tx.clone();
    assert!(tx_str.aggregate(ProofType::Succinct).is_ok());

    tx_str.actions[0].logic_verifier_inputs.pop();

    assert!(tx_str.verify_aggregation().is_err());
}

/// SEC-006: Can the batch aggregation circuit produce a valid proof for
/// a zero-action transaction?
#[test]
fn test_empty_transaction_aggregation() {
    use anoma_rm_risc0::CoreDeltaProof as DeltaProof;

    // Create a transaction with zero actions
    let empty_tx = Transaction {
        actions: vec![],
        delta_proof: Delta::Proof(DeltaProof([0u8; 65])),
        expected_balance: None,
        aggregation_proof: None,
    };

    // base_proofs_are_empty returns false for zero actions (no proofs to check)
    assert!(
        !empty_tx.base_proofs_are_empty(),
        "zero actions means no empty proofs — the check passes"
    );

    // Attempt aggregation — this actually runs the risc0 prover (dev mode)
    let mut tx = empty_tx.clone();
    let result = tx.aggregate(ProofType::Succinct);

    println!("Empty tx aggregation result: {:?}", result.is_ok());
    if let Ok(()) = &result {
        println!(
            "aggregation_proof present: {}",
            tx.aggregation_proof.is_some()
        );
        if let Some(proof) = &tx.aggregation_proof {
            println!("proof size: {} bytes", proof.len());
        }
        // Try to verify the aggregated proof
        let verify_result = tx.verify_aggregation();
        println!("verify_aggregation result: {:?}", verify_result.is_ok());
    } else {
        println!("Aggregation failed: {:?}", result.err());
    }
}

#[test]
fn test_cannot_aggregate_invalid_proofs() {
    use anoma_rm_risc0::LogicVerifierInputs;

    let tx = generate_test_transaction(2, 2, ProofType::Succinct);

    // Create a transaction with one invalid proof.
    let bad_lproof = LogicVerifierInputs {
        proof: tx.actions[0].logic_verifier_inputs[0].clone().proof,
        verifying_key: Digest::try_from([66u8; 32].as_slice()).unwrap(), // Bad key.
        tag: tx.actions[0].logic_verifier_inputs[0].tag,
        app_data: tx.actions[0].logic_verifier_inputs[0].app_data.clone(),
    };

    let bad_action = Action {
        compliance_units: tx.actions[0].clone().compliance_units,
        logic_verifier_inputs: vec![bad_lproof],
    };
    let bad_tx = Transaction::create(vec![bad_action, tx.actions[1].clone()], tx.delta_proof);

    let mut bad_tx_str = bad_tx.clone();
    assert!(bad_tx_str.aggregate(ProofType::Succinct).is_err());
    assert!(bad_tx_str.aggregation_proof.is_none());
}
