// This module contains a trivial test circuit and tx tests for the ARM crate.
// The functions here are also used in the elixir sdk and binding libraries to
// ensure that the ARM crate's transaction functionalities work as expected.

use std::time::{Duration, Instant};

use crate::{
    action::Action,
    compliance::{
        ComplianceSigmabusWitness, ComplianceVarWitness, ComplianceWitness, TX_MAX_RESOURCES,
    },
    compliance_unit::{ComplianceSigmabusUnit, ComplianceUnit, ComplianceVarUnit, CUI},
    delta_proof::DeltaWitness,
    logic_proof::{LogicProver, PaddingResourceLogic},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    test_logic::TestLogicWitness,
    transaction::{Delta, Transaction},
};
use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::{
    sha::{Impl, Sha256},
    Digest,
};
use serde::{Deserialize, Serialize};

// Test logic proving key / test logic guest ELF binary
pub const TEST_LOGIC_PK: &[u8] = include_bytes!("../elfs/logic-test-guest.bin");

lazy_static! {
    // test logic verification key / compliance image id
    pub static ref TEST_LOGIC_VK: Digest =
        Digest::from_hex("34c7de7531d47a21c896ca0dc719e3b4c525c26d8f56034517bc2bf7edfb80f5")
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
) -> (Action<ComplianceUnit>, DeltaWitness) {
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
    let mut nullifiers = Vec::new();
    let mut commitments = Vec::new();
    for i in 0..compliance_num {
        let compliance_witness = ComplianceWitness::with_fixed_rcv(
            consumed_resources[i],
            nf_key.clone(),
            created_resources[i],
        );
        let compliance_receipt = ComplianceUnit::create(&compliance_witness).unwrap();

        let consumed_resource_nf = consumed_resources[i].nullifier(&nf_key).unwrap();
        let created_resource_cm = created_resources[i].commitment();

        nullifiers.push(consumed_resource_nf);
        commitments.push(created_resource_cm);

        compliance_units.push(compliance_receipt);
        rcvs.push(compliance_witness.rcv);
    }
    let action_tree = Action::<ComplianceUnit>::construct_action_tree(&nullifiers, &commitments);

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
            let consumed_logic_proof = consumed_logic.prove().unwrap();

            let created_logic = TestLogic::new(
                created_resources[i],
                created_resource_path,
                nf_key.clone(),
                false,
            );
            let created_logic_proof = created_logic.prove().unwrap();

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
) -> (Vec<Action<ComplianceUnit>>, DeltaWitness) {
    let mut actions = Vec::new();
    let mut delta_witnesses = Vec::new();
    for i in 0..action_num {
        let (action, delta_witness) =
            create_an_action_with_multiple_compliances(compliance_num, i as u8);
        actions.push(action);
        delta_witnesses.push(delta_witness);
    }
    (actions, DeltaWitness::compress(&delta_witnesses))
}

// Create a test transaction with n_actions actions, each with compliance_num compliance units
pub fn generate_test_transaction(
    n_actions: usize,
    compliance_num: usize,
) -> Transaction<ComplianceUnit> {
    let (actions, delta_witness) = create_multiple_actions(n_actions, compliance_num);
    let tx = Transaction::create(actions, Delta::Witness(delta_witness));
    let balanced_tx = tx.generate_delta_proof().unwrap();
    balanced_tx.clone().verify().unwrap();
    balanced_tx
}

/// Returns `num` dummy resources, their nullifiers, and their nullifier keys (for convenience).
/// They all have the same logic ([TestLogic]) and quantity 1.
fn dummy_consumed_resources(num: u32) -> (Vec<Resource>, Vec<Digest>, Vec<NullifierKey>) {
    let (nf_key, nf_key_cm) = NullifierKey::random_pair();
    let (consumed_resources, consumed_nullifiers): (Vec<Resource>, Vec<Digest>) = (0..num)
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
            let consumed_nf = consumed_resource.nullifier(&nf_key).unwrap();

            (consumed_resource, consumed_nf)
        })
        .unzip();

    (
        consumed_resources,
        consumed_nullifiers,
        vec![nf_key; num as usize],
    )
}

/// Returns `num` dummy resources. They all have the same logic ([TestLogic]),
/// and their nonces are derived from the passed nullifiers.
fn dummy_created_resources(num: u32, consumed_nullifiers: &[Digest]) -> Vec<Resource> {
    let nullifiers_digest = {
        let mut bytes = Vec::new();
        for nf in consumed_nullifiers.iter() {
            bytes.append(&mut nf.as_bytes().to_vec().clone());
        }

        Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap()
    };

    (0..num)
        .map(|index| {
            let quantity = if index == 0 { num } else { 0 };
            let mut created_resource = Resource {
                logic_ref: TestLogic::verifying_key(),
                nk_commitment: NullifierKey::default().commit(),
                quantity: quantity as u128,
                ..Default::default()
            };
            created_resource.nonce =
                Resource::derive_nonce(index as usize, nullifiers_digest).unwrap();

            created_resource
        })
        .collect()
}

/// Creates as many two-sized compliance units as necessary to fit `old_num` consumed resources
/// and `new_num` created resources. Padding resources are added as necessary.
/// To bench against compliance units of variable size (assume `old_num` >= `new_num`).
pub fn create_compliance_units(old_num: u32, new_num: u32) -> Vec<ComplianceUnit> {
    assert!(old_num >= new_num);

    // Generate consumed resources and their nullifiers
    let (consumed_resources, consumed_nullifiers, nf_keys) = dummy_consumed_resources(old_num);

    // Generate created resources
    let created_resources: Vec<Resource> = (0..new_num)
        .map(|index| {
            let quantity = if index == 0 { old_num } else { 0 };
            let mut created_resource = Resource {
                logic_ref: TestLogic::verifying_key(),
                nk_commitment: NullifierKey::default().commit(),
                quantity: quantity as u128,
                ..Default::default()
            };
            created_resource.set_nonce(consumed_nullifiers[index as usize]);
            created_resource
        })
        .collect();

    // Generate `old_num` witnessess for the compliance unit circuit
    let mut witnessess = Vec::new();
    for i in 0..old_num {
        let created_or_padding = if i < new_num {
            created_resources[i as usize]
        } else {
            let mut pad =
                PaddingResourceLogic::create_padding_resource(NullifierKey::default().commit());
            let nf_key = nf_keys[i as usize].clone();
            pad.set_nonce(consumed_resources[i as usize].nullifier(&nf_key).unwrap());
            pad
        };
        let compliance_witness = ComplianceWitness::with_fixed_rcv(
            consumed_resources[i as usize],
            nf_keys[i as usize].clone(),
            created_or_padding,
        );
        witnessess.push(compliance_witness);
    }

    // Prove compliance
    let mut cus = Vec::new();
    let mut prove_total = Duration::ZERO;

    for witness in witnessess {
        let prove_timer = Instant::now();

        let cu = ComplianceUnit::create(&witness).unwrap();

        let prove_single_cu = prove_timer.elapsed();
        prove_total += prove_single_cu;

        cus.push(cu);
    }
    let alignment_overhead = prove_total
        .div_f64((2 * old_num) as f64)
        .mul_f64((old_num - new_num) as f64);

    // circuit; resources; (consumed, created); proving time; #cu; alignment overhead
    println!(
        "2 sized; {:?}; ({:?}, {:?}); {:?}; {:?}; {:?}",
        old_num + new_num,
        old_num,
        new_num,
        prove_total,
        cus.len(),
        alignment_overhead
    );

    cus
}

/// Creates a variable-sized compliance unit with `old_num` consumed resources and `new_num` created resources.
/// For simplicity, assume `old_num` >= `new_num`.
pub fn create_compliance_var_unit(old_num: u32, new_num: u32) -> ComplianceVarUnit {
    assert!(old_num >= new_num);

    // Generate consumed resources and their nullifiers
    let (consumed_resources, consumed_nullifiers, nf_keys) = dummy_consumed_resources(old_num);

    // Generate created resources
    let created_resources = dummy_created_resources(new_num, &consumed_nullifiers);

    // Set the witness to the compliance var circuit
    let compliance_witness =
        ComplianceVarWitness::with_fixed_rcv(&consumed_resources, &nf_keys, &created_resources);

    // Prove compliance
    let prove_timer = Instant::now();

    let cu_var = ComplianceVarUnit::create(&compliance_witness).unwrap();

    let prove_duration = prove_timer.elapsed();

    // circuit; resources; (consumed, created); proving time; #cu
    println!(
        "var; {:?}; ({:?}, {:?}); {:?}; 1",
        old_num + new_num,
        old_num,
        new_num,
        prove_duration
    );

    cu_var
}

pub fn create_compliance_sigmabus_unit(old_num: u32, new_num: u32) -> ComplianceSigmabusUnit {
    // Generate consumed resources and their nullifiers
    let (consumed_resources, consumed_nullifiers, nf_keys) = dummy_consumed_resources(old_num);

    // Generate created resources
    let created_resources = dummy_created_resources(new_num, &consumed_nullifiers);

    // Set the witness to the compliance var circuit
    let compliance_witness = ComplianceSigmabusWitness::from_resources_with_fixed_path(
        &consumed_resources,
        &nf_keys,
        &created_resources,
    )
    .unwrap();

    // Prove compliance
    let prove_timer = Instant::now();

    let cu_sigmabus = ComplianceSigmabusUnit::create(&compliance_witness).unwrap();

    let prove_duration = prove_timer.elapsed();

    // circuit; resources; (consumed, created); proving time; #cu
    println!(
        "sigmabus-{:?}; {:?}; ({:?}, {:?}); {:?}; 1",
        TX_MAX_RESOURCES,
        old_num + new_num,
        old_num,
        new_num,
        prove_duration
    );

    cu_sigmabus
}

#[test]
fn test_logic_prover() {
    let test_logic = TestLogic::default();
    let proof = test_logic.prove().unwrap();
    proof.verify().unwrap();
}

#[test]
fn test_action() {
    let _ = create_an_action_with_multiple_compliances(2, 1);
}

#[test]
fn test_transaction() {
    let _ = generate_test_transaction(2, 2);
}

#[test]
fn test_compliance_var_unit_works() {
    let cu_var = create_compliance_var_unit(5, 3);
    assert!(cu_var.verify().is_ok());
}

#[test]
fn test_compliance_sigmabus_unit_works() {
    assert!(TX_MAX_RESOURCES > 8);
    let cu_sigmabus = create_compliance_sigmabus_unit(5, 3);
    assert!(cu_sigmabus.verify().is_ok());
}

#[test]
fn bench_compliance_2_var_sigmabus() {
    println!("2 vs VAR");
    println!("circuit; resources; (consumed, created); proving time; #cu; alignment overhead");
    let mut number_resources: Vec<(u32, u32)> = vec![(1, 1), (2, 1), (2, 2), (4, 4), (7, 1)];
    for (old_num, new_num) in number_resources.into_iter() {
        create_compliance_units(old_num, new_num);
        create_compliance_var_unit(old_num, new_num);
    }

    println!("2 -- FULLY UNALIGNED");
    println!("circuit; resources; (consumed, created); proving time; #cu; alignment overhead");
    number_resources = vec![(1, 1), (2, 1), (3, 1), (4, 1), (5, 1), (6, 1), (7, 1)];
    for (old_num, new_num) in number_resources.into_iter() {
        create_compliance_units(old_num, new_num);
    }

    println!("VAR vs SIGMABUS");
    println!("circuit; resources; (consumed, created); proving time; #cu;");
    number_resources = vec![
        (1, 1),
        (3, 1),
        (7, 1),
        (15, 1),
        (23, 1),
        (31, 1),
        (39, 1),
        (47, 1),
        (55, 1),
        (63, 1),
        (71, 1),
        (79, 1),
        (87, 1),
        (95, 1),
        (103, 1),
        (111, 1),
        (119, 1),
        (127, 1),
    ];
    for (old_num, new_num) in number_resources.into_iter() {
        create_compliance_var_unit(old_num, new_num);
        if (old_num + new_num) as usize <= TX_MAX_RESOURCES {
            create_compliance_sigmabus_unit(old_num, new_num);
        }
    }

    println!("DONE.")
}

#[test]
#[cfg(feature = "aggregation")]
fn test_aggregation_works() {
    use crate::aggregation::AggregationStrategy;

    let tx = generate_test_transaction(2, 2);

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

    let tx = generate_test_transaction(2, 2);

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

    let tx = generate_test_transaction(2, 2);

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
