// This module contains a trivial test circuit and tx tests for the ARM crate.
// The functions here are also used in the elixir sdk and binding libraries to
// ensure that the ARM crate's transaction functionalities work as expected.

use crate::{
    action::Action,
    action_tree::MerkleTree,
    compliance::ComplianceWitness,
    compliance_unit::ComplianceUnit,
    delta_proof::DeltaWitness,
    logic_proof::LogicProver,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    test_logic::TestLogicWitness,
    transaction::{Delta, Transaction},
};
use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;
use serde::{Deserialize, Serialize};

// Test logic proving key / test logic guest ELF binary
pub const TEST_LOGIC_PK: &[u8] = include_bytes!("../elfs/logic-test-guest.bin");

lazy_static! {
    // test logic verification key / compliance image id
    pub static ref TEST_LOGIC_VK: Digest =
        Digest::from_hex("4f090a77ffbc5950055be7521932a69d277260082ebb4b24349abca5245d00f6")
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

pub fn create_an_action(nonce: u8) -> (Action, DeltaWitness) {
    let nf_key = NullifierKey::default();
    let nf_key_cm = nf_key.commit();
    let mut consumed_resource = Resource {
        logic_ref: TestLogic::verifying_key(),
        nk_commitment: nf_key_cm,
        quantity: 1,
        ..Default::default()
    };
    consumed_resource.nonce[0] = nonce;
    let consumed_resource_nf = consumed_resource.nullifier(&nf_key).unwrap();

    let mut created_resource = consumed_resource.clone();
    created_resource.set_nonce(consumed_resource_nf);

    let compliance_witness = ComplianceWitness::with_fixed_rcv(
        consumed_resource.clone(),
        nf_key.clone(),
        created_resource.clone(),
    );
    let compliance_receipt = ComplianceUnit::create(&compliance_witness).unwrap();

    let created_resource_cm = created_resource.commitment();
    let action_tree = MerkleTree::new(vec![consumed_resource_nf, created_resource_cm]);
    let consumed_resource_path = action_tree.generate_path(&consumed_resource_nf).unwrap();
    let created_resource_path = action_tree.generate_path(&created_resource_cm).unwrap();

    let consumed_logic = TestLogic::new(
        consumed_resource,
        consumed_resource_path,
        nf_key.clone(),
        true,
    );
    let consumed_logic_proof = consumed_logic.prove().unwrap();

    let created_logic = TestLogic::new(created_resource, created_resource_path, nf_key, false);
    let created_logic_proof = created_logic.prove().unwrap();

    let compliance_units = vec![compliance_receipt];
    let logic_verifier_inputs = vec![consumed_logic_proof, created_logic_proof];

    let action = Action::new(compliance_units, logic_verifier_inputs).unwrap();
    action.clone().verify().unwrap();

    let delta_witness = DeltaWitness::from_bytes_vec(&[compliance_witness.rcv]).unwrap();
    (action, delta_witness)
}

pub fn create_multiple_actions(n: usize) -> (Vec<Action>, DeltaWitness) {
    let mut actions = Vec::new();
    let mut delta_witnesses = Vec::new();
    for i in 0..n {
        let (action, delta_witness) = create_an_action(i as u8);
        actions.push(action);
        delta_witnesses.push(delta_witness);
    }
    (actions, DeltaWitness::compress(&delta_witnesses))
}

pub fn generate_test_transaction(n_actions: usize) -> Transaction {
    let (actions, delta_witness) = create_multiple_actions(n_actions);
    let tx = Transaction::create(actions, Delta::Witness(delta_witness));
    let balanced_tx = tx.generate_delta_proof().unwrap();
    balanced_tx.clone().verify().unwrap();
    balanced_tx
}

#[test]
fn test_logic_prover() {
    let test_logic = TestLogic::default();
    let proof = test_logic.prove().unwrap();
    proof.verify().unwrap();
}

#[test]
fn test_action() {
    let _ = create_an_action(1);
}

#[test]
fn test_transaction() {
    let _ = generate_test_transaction(1);
}

#[test]
#[cfg(feature = "aggregation")]
fn test_aggregation_works() {
    use crate::aggregation::AggregationStrategy;

    let tx = generate_test_transaction(1);

    for strategy in [AggregationStrategy::Sequential, AggregationStrategy::Batch] {
        let mut tx_str = tx.clone();
        assert!(tx_str.aggregate_with_strategy(strategy.clone()).is_ok());
        assert!(tx_str.aggregation_proof.is_some());
        assert!(tx_str.verify_aggregation().is_ok());
    }
}

#[test]
#[cfg(feature = "aggregation")]
fn test_verify_aggregation_fails_for_incorrect_instances() {
    use crate::aggregation::AggregationStrategy;

    let tx = generate_test_transaction(2);

    for strategy in [AggregationStrategy::Sequential, AggregationStrategy::Batch] {
        let mut tx_str = tx.clone();
        assert!(tx_str.aggregate_with_strategy(strategy).is_ok());

        tx_str.actions[0].logic_verifier_inputs.pop();

        assert!(tx_str.verify_aggregation().is_err());
    }
}

#[test]
#[cfg(feature = "aggregation")]
fn test_cannot_aggregate_invalid_proofs() {
    use crate::{aggregation::AggregationStrategy, logic_proof::LogicVerifierInputs};

    let tx = generate_test_transaction(2);

    // Create a transaction with one invalid proof.
    let bad_lproof = LogicVerifierInputs {
        proof: tx.actions[0].logic_verifier_inputs[0].clone().proof,
        verifying_key: Digest::from_bytes([66u8; 32]), //vec![666u32; 8], // Bad key.
        tag: tx.actions[0].logic_verifier_inputs[0].tag,
        app_data: tx.actions[0].logic_verifier_inputs[0].app_data.clone(),
    };

    let bad_action = Action {
        compliance_units: tx.actions[0].clone().compliance_units,
        logic_verifier_inputs: vec![bad_lproof],
    };
    let bad_tx = Transaction::create(vec![bad_action, tx.actions[1].clone()], tx.delta_proof);

    for strategy in [AggregationStrategy::Sequential, AggregationStrategy::Batch] {
        let mut bad_tx_str = bad_tx.clone();
        assert!(bad_tx_str.aggregate_with_strategy(strategy).is_err());
        assert!(bad_tx_str.aggregation_proof.is_none());
    }
}
