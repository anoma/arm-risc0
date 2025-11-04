// This module contains a trivial test circuit and tx tests for the ARM crate.
// The functions here are also used in the elixir sdk and binding libraries to
// ensure that the ARM crate's transaction functionalities work as expected.

use crate::{
    action::Action,
    compliance::ComplianceWitness,
    compliance_unit::ComplianceUnit,
    delta_proof::DeltaWitness,
    error::ArmError,
    logic_proof::{LogicProver, LogicVerifier},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::{ConsumedDatum, Resource},
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
        Digest::from_hex("de5d06d0066964aca9a184773e1832df031e6077227bb60607d5fe49aa0a5b43")
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

#[derive(Default)]
pub struct Tester {
    /// Consumed resources across all actions
    pub consumed_data: Vec<Vec<ConsumedDatum>>,
    /// Created resources across all actions
    pub created_resources: Vec<Vec<Resource>>,
    /// The randomness of the delta commitments for each CU/action.
    pub rcvs: Vec<Vec<u8>>,
    // Internal counter -- current action.
    current: usize,
}

impl Tester {
    /// Populates the tester with `num` test resources, their merkle paths, and their nullifier keys.
    /// They all have the same logic ([TestLogic]) and quantity 1.
    pub fn populate_consumed_resources(&mut self, num: u32) {
        let (nf_key, nf_key_cm) = NullifierKey::random_pair();
        let consumed_resources: Vec<Resource> = (0..num)
            .map(|index| {
                let mut consumed_resource = Resource {
                    logic_ref: TestLogic::verifying_key(),
                    nk_commitment: nf_key_cm,
                    quantity: 1,
                    ..Default::default()
                };
                consumed_resource.nonce = [
                    index.to_be_bytes(),
                    index.to_be_bytes(),
                    index.to_be_bytes(),
                    index.to_be_bytes(),
                    index.to_be_bytes(),
                    index.to_be_bytes(),
                    index.to_be_bytes(),
                    index.to_be_bytes(),
                ]
                .concat()
                .try_into()
                .unwrap();

                consumed_resource
            })
            .collect();

        let consumed_data = consumed_resources
            .into_iter()
            .map(|resource| ConsumedDatum::from_resource(resource, nf_key.clone()))
            .collect::<Vec<ConsumedDatum>>();

        self.consumed_data.push(consumed_data);
    }

    /// Populates the tester with `num` created resources. They all have the same logic ([TestLogic]),
    /// and their nonces are derived from the passed nullifiers.
    pub fn populate_created_resources(&mut self, num: u32) {
        assert!(!self.consumed_data.is_empty());
        let nullifiers = self.consumed_data[self.current] // Grab consumed data of current CU/action
            .iter()
            .map(|memo| memo.resource.nullifier(&memo.nf_key).unwrap())
            .collect::<Vec<Digest>>();

        let created_resources = (0..num)
            .map(|index| {
                let mut created_resource = Resource {
                    logic_ref: TestLogic::verifying_key(),
                    nk_commitment: NullifierKey::default().commit(),
                    quantity: 1,
                    ..Default::default()
                };
                created_resource.nonce =
                    Resource::derive_nonce_from_nullifiers(index as usize, &nullifiers).unwrap();

                created_resource
            })
            .collect::<Vec<Resource>>();

        self.created_resources.push(created_resources);
    }

    /// Creates a compliance unit with `old_num` consumed resources and `new_num` created resources.
    pub fn create_compliance_unit(
        &mut self,
        old_num: u32,
        new_num: u32,
    ) -> Result<ComplianceUnit, ArmError> {
        self.populate_consumed_resources(old_num);
        self.populate_created_resources(new_num);

        let compliance_witness = ComplianceWitness::from_resources_info(
            &self.consumed_data[self.current],
            &self.created_resources[self.current],
        );

        self.rcvs.push(compliance_witness.rcv.clone());

        ComplianceUnit::create(&compliance_witness)
    }

    /// Creates an action with `old_num` consumed resources and `new_num`  created resources.
    pub fn create_an_action(&mut self, old_num: u32, new_num: u32) -> Result<Action, ArmError> {
        let compliance_unit = self.create_compliance_unit(old_num, new_num)?;

        let mut tags = self.consumed_data[self.current]
            .iter()
            .map(|consumed_datum| {
                consumed_datum
                    .resource
                    .nullifier(&consumed_datum.nf_key)
                    .unwrap()
            })
            .chain(
                self.created_resources[self.current]
                    .iter()
                    .map(|created_resource| created_resource.commitment()),
            )
            .collect::<Vec<Digest>>();

        tags.reverse(); // test that tag ordering is unimportant
        let action_tree = Action::construct_action_tree(&tags);

        let logic_verifiers = self.consumed_data[self.current]
            .iter()
            .map(|consumed_datum| (consumed_datum.resource, consumed_datum.nf_key.clone(), true))
            .chain(
                self.created_resources[self.current]
                    .iter()
                    .map(|created_resource| (*created_resource, NullifierKey::default(), false)),
            )
            .map(|res_nfkey_isconsumed| {
                let (resource, nf_key, is_consumed) = res_nfkey_isconsumed;

                let tag = if is_consumed {
                    resource.nullifier(&nf_key).unwrap()
                } else {
                    resource.commitment()
                };

                let receive_existence_path = action_tree.generate_path(&tag).unwrap();

                let test_logic =
                    TestLogic::new(resource, receive_existence_path, nf_key, is_consumed);
                test_logic.prove().unwrap()
            })
            .collect::<Vec<LogicVerifier>>();

        let action = Action::new(compliance_unit, logic_verifiers).unwrap();

        self.current += 1; // Update to next action

        Ok(action)
    }

    /// Creates several actions, each with the passed number of consumed (old) resources, and created (new) resources.
    pub fn create_multiple_actions(
        &mut self,
        old_new_resources_nums: &[(u32, u32)],
    ) -> Result<Vec<Action>, ArmError> {
        let mut actions = Vec::new();
        for (old_num, new_num) in old_new_resources_nums.iter() {
            actions.push(self.create_an_action(*old_num, *new_num)?);
        }
        Ok(actions)
    }

    /// Creates a test transaction with several actions. Each action with the passed number of consumed (old) resources, and created (new) resources.
    pub fn generate_test_transaction(
        &mut self,
        old_new_resources_nums: &[(u32, u32)],
    ) -> Result<Transaction, ArmError> {
        let actions = self.create_multiple_actions(old_new_resources_nums)?;
        let delta_witness = DeltaWitness::from_bytes_vec(&self.rcvs).unwrap();

        let tx = Transaction::create(actions, Delta::Witness(delta_witness));
        let tx_with_delta = tx.generate_delta_proof().unwrap();

        Ok(tx_with_delta)
    }
}

#[test]
fn test_logic_prover() {
    let test_logic = TestLogic::default();
    let proof = test_logic.prove().unwrap();
    proof.verify().unwrap();
}

#[test]
fn test_compliance_unit() {
    let compliance_unit = Tester::default().create_compliance_unit(3, 2).unwrap();
    assert!(compliance_unit.verify().is_ok())
}

#[test]
fn test_compliance_unit_must_consume_resources() {
    let compliance_unit = Tester::default().create_compliance_unit(0, 1);
    assert!(compliance_unit.is_err())
}

#[test]
fn test_action() {
    let action = Tester::default().create_an_action(3, 2).unwrap();
    assert!(action.verify().is_ok())
}

#[test]
fn test_transaction() {
    let balanced_tx = Tester::default()
        .generate_test_transaction(&[(2, 1), (1, 2)])
        .unwrap();
    assert!(balanced_tx.verify().is_ok())
}

#[test]
fn test_unbalanced_tx_fails_to_verify() {
    let unbalanced_tx = Tester::default()
        .generate_test_transaction(&[(2, 1), (1, 1)])
        .unwrap();
    assert!(unbalanced_tx.verify().is_err())
}

#[test]
fn test_unmatched_logic_verifier_inputs_in_action() {
    let actions = Tester::default()
        .create_multiple_actions(&[(1, 1), (1, 1)])
        .unwrap();
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
    let mut tx = Tester::default()
        .generate_test_transaction(&[(1, 1), (1, 1)])
        .unwrap();
    assert!(tx.nf_duplication_check().is_ok());

    // Introduce a duplicate nullifier
    tx.actions[1] = tx.actions[0].clone();

    assert!(tx.nf_duplication_check().is_err());
}
#[test]
#[cfg(feature = "aggregation")]
fn test_aggregation_works() {
    use crate::aggregation::AggregationStrategy;

    let tx = Tester::default()
        .generate_test_transaction(&[(2, 2), (2, 2)])
        .unwrap();

    for strategy in [AggregationStrategy::Sequential, AggregationStrategy::Batch] {
        let mut tx_str = tx.clone();
        assert!(tx_str.aggregate_with_strategy(strategy.clone()).is_ok());
        assert!(tx_str.aggregation_proof.is_some());
        assert!(tx_str.verify_aggregation().is_ok());
        assert!(tx_str.verify().is_ok());
    }

    // In case no aggregation, can still verify all individual proofs.
    assert!(tx.aggregation_proof.is_none());
    assert!(tx.verify().is_ok());
}

#[test]
#[cfg(feature = "aggregation")]
fn test_verify_aggregation_fails_for_incorrect_instances() {
    use crate::aggregation::AggregationStrategy;

    let tx = Tester::default()
        .generate_test_transaction(&[(2, 2), (2, 2)])
        .unwrap();

    for strategy in [AggregationStrategy::Sequential, AggregationStrategy::Batch] {
        let mut tx_str = tx.clone();
        assert!(tx_str.aggregate_with_strategy(strategy).is_ok());

        tx_str.actions[0].logic_verifier_inputs.pop();

        assert!(tx_str.verify_aggregation().is_err());
        assert!(tx_str.verify().is_err());
    }
}

#[test]
#[cfg(feature = "aggregation")]
fn test_cannot_aggregate_invalid_proofs() {
    use crate::{aggregation::AggregationStrategy, logic_proof::LogicVerifierInputs};

    let tx = Tester::default()
        .generate_test_transaction(&[(2, 2), (2, 2)])
        .unwrap();

    // Create a transaction with one invalid proof.
    let bad_lproof = LogicVerifierInputs {
        proof: tx.actions[0].logic_verifier_inputs[0].clone().proof,
        verifying_key: Digest::from_bytes([66u8; 32]), //vec![666u32; 8], // Bad key.
        tag: tx.actions[0].logic_verifier_inputs[0].tag,
        app_data: tx.actions[0].logic_verifier_inputs[0].app_data.clone(),
    };

    let bad_action = Action {
        compliance_unit: tx.actions[0].clone().compliance_unit,
        logic_verifier_inputs: vec![bad_lproof],
    };
    let bad_tx = Transaction::create(vec![bad_action, tx.actions[1].clone()], tx.delta_proof);

    for strategy in [AggregationStrategy::Sequential, AggregationStrategy::Batch] {
        let mut bad_tx_str = bad_tx.clone();
        assert!(bad_tx_str.aggregate_with_strategy(strategy).is_err());
        assert!(bad_tx_str.aggregation_proof.is_none());
    }
}
