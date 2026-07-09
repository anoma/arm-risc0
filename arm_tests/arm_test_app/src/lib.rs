// This module contains a trivial test circuit and tx tests for the ARM crate.
// The functions here are also used in the elixir sdk and binding libraries to
// ensure that the ARM crate's transaction functionalities work as expected.

use anoma_rm_risc0::{
    action::Action,
    compliance::ComplianceWitness,
    compliance_unit::ComplianceUnit,
    constants::{global_kind_table, init_kind_table_from_file},
    delta_proof::DeltaWitness,
    error::ArmError,
    logic_proof::{LogicProver, LogicVerifier},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    proving_system::ProofType,
    resource::{ConsumedResourceWitness, Resource},
    transaction::{Delta, Transaction},
    Digest,
};
#[cfg(test)]
use anoma_rm_risc0::{
    compliance::ComplianceInstance,
    proving_system::{instance_to_journal, journal_to_instance},
};
use anoma_rm_risc0_test_witness::TestLogicWitness;
use hex::FromHex;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

// Test logic proving key / test logic guest ELF binary
pub const TEST_LOGIC_PK: &[u8] = include_bytes!("../elf/logic-test-guest.bin");

lazy_static! {
    // test logic verification key / compliance image id
    pub static ref TEST_LOGIC_VK: Digest =
        Digest::from_hex("755cc2329435fc0ce768ab44572ec2c1ccc4a84afad58c890a0eec74a96040ff")
            .unwrap();
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct TestLogic {
    witness: TestLogicWitness,
}

impl TestLogic {
    pub fn new(
        resource: Resource,
        action_tree_path: MerklePath,
        nf_key: NullifierKey,
        is_consumed: bool,
    ) -> Self {
        let witness = TestLogicWitness {
            resource,
            action_tree_path,
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
    pub consumed_data: Vec<Vec<ConsumedResourceWitness>>,
    /// Created resources across all actions
    pub created_resources: Vec<Vec<Resource>>,
    /// The randomness of the delta commitments for each CU/action.
    pub rcvs: Vec<Vec<u8>>,
    // Internal counter -- current action.
    current: usize,
}

impl Tester {
    /// Populates the tester with `num` test consumed-resource witnesses, all
    /// signed by the same fresh nullifier key, with the same [TestLogic] and
    /// quantity 1, and per-resource distinct nonces.
    pub fn populate_consumed_resources(&mut self, num: u32) {
        let (nf_key, nk_commitment) = NullifierKey::random_pair();
        let consumed_data = (0..num)
            .map(|index| {
                let resource = Resource {
                    logic_ref: TestLogic::verifying_key(),
                    nk_commitment,
                    quantity: 1,
                    nonce: nonce_from_index(index),
                    ..Default::default()
                };
                ConsumedResourceWitness::from_resource(resource, nf_key.clone())
            })
            .collect();
        self.consumed_data.push(consumed_data);
    }

    /// Populates the tester with `num` created resources for the current action.
    /// They share the same [TestLogic] and quantity 1; nonces are derived from
    /// the consumed nullifiers, which must already be populated for this action.
    pub fn populate_created_resources(&mut self, num: u32) -> Result<(), ArmError> {
        let consumed = self
            .consumed_data
            .get(self.current)
            .ok_or(ArmError::MissingField("consumed_data"))?;
        let nullifiers: Vec<Digest> = consumed
            .iter()
            .map(|w| w.resource.nullifier(&w.nf_key).unwrap())
            .collect();

        let created_resources = (0..num)
            .map(|index| -> Result<Resource, ArmError> {
                Ok(Resource {
                    logic_ref: TestLogic::verifying_key(),
                    nk_commitment: NullifierKey::default().commit(),
                    quantity: 1,
                    nonce: Resource::derive_nonce_from_nullifiers(index, &nullifiers)?,
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        self.created_resources.push(created_resources);
        Ok(())
    }

    /// Creates a compliance unit with `consumed_num` consumed and `created_num` created
    /// resources for the current action.
    pub fn create_compliance_unit(
        &mut self,
        consumed_num: u32,
        created_num: u32,
    ) -> Result<ComplianceUnit, ArmError> {
        self.populate_consumed_resources(consumed_num);
        self.populate_created_resources(created_num)?;

        init_test_kind_table();
        let compliance_witness = ComplianceWitness::from_resources(
            &self.consumed_data[self.current],
            &self.created_resources[self.current],
            global_kind_table().to_vec(),
        );
        self.rcvs.push(compliance_witness.rcv.clone());

        ComplianceUnit::create(&compliance_witness, ProofType::Succinct)
    }

    /// Creates an action with `consumed_num` consumed and `created_num` created resources.
    pub fn create_an_action(
        &mut self,
        consumed_num: u32,
        created_num: u32,
    ) -> Result<Action, ArmError> {
        let compliance_unit = self.create_compliance_unit(consumed_num, created_num)?;

        // Build (tag, resource, nf_key, is_consumed) entries in the compliance
        // unit's canonical tag order (consumed nullifiers, then created
        // commitments) — exactly what `ComplianceInstance::tags()` returns.
        // Computing the tag once here avoids re-deriving it inside the
        // verifier loop.
        let consumed = &self.consumed_data[self.current];
        let created = &self.created_resources[self.current];
        let entries: Vec<(Digest, Resource, NullifierKey, bool)> = consumed
            .iter()
            .map(|w| {
                let tag = w.resource.nullifier(&w.nf_key).unwrap();
                (tag, w.resource, w.nf_key.clone(), true)
            })
            .chain(
                created
                    .iter()
                    .map(|r| (r.commitment(), *r, NullifierKey::default(), false)),
            )
            .collect();

        let tags: Vec<Digest> = entries.iter().map(|(tag, ..)| *tag).collect();
        let action_tree = Action::construct_action_tree(&tags);

        let logic_verifiers = entries
            .into_iter()
            .map(|(tag, resource, nf_key, is_consumed)| {
                let action_tree_path = action_tree.generate_path(&tag).unwrap();
                TestLogic::new(resource, action_tree_path, nf_key, is_consumed)
                    .prove(ProofType::Succinct)
                    .unwrap()
            })
            .collect::<Vec<LogicVerifier>>();

        let action = Action::new(compliance_unit, logic_verifiers).unwrap();
        self.current += 1;
        Ok(action)
    }

    /// Creates several actions; each `(consumed, created)` pair becomes one action.
    pub fn create_multiple_actions(
        &mut self,
        consumed_created_nums: &[(u32, u32)],
    ) -> Result<Vec<Action>, ArmError> {
        consumed_created_nums
            .iter()
            .map(|(consumed, created)| self.create_an_action(*consumed, *created))
            .collect()
    }

    /// Creates a test transaction with one action per `(consumed, created)`
    /// pair, and generates the delta proof.
    pub fn generate_test_transaction(
        &mut self,
        consumed_created_nums: &[(u32, u32)],
    ) -> Result<Transaction, ArmError> {
        let actions = self.create_multiple_actions(consumed_created_nums)?;
        Transaction::create(actions, Delta::Witness(self.delta_witness())).generate_delta_proof()
    }

    /// Builds a `DeltaWitness` from the per-CU randomness collected so far.
    /// Use this rather than reaching into the `rcvs` field directly.
    pub fn delta_witness(&self) -> DeltaWitness {
        DeltaWitness::from_bytes_vec(&self.rcvs).unwrap()
    }

    /// Test-only escape hatch: overwrites the nonce of an already-populated
    /// created resource. Reaching into `created_resources` directly is
    /// possible but couples the test to an internal layout that may change.
    pub fn set_created_nonce(&mut self, action_idx: usize, resource_idx: usize, nonce: [u8; 32]) {
        self.created_resources[action_idx][resource_idx].nonce = nonce;
    }
}

fn init_test_kind_table() {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../arm/kind_table.json");
    init_kind_table_from_file(&path).expect("Failed to load kind_table.json");
}

#[cfg(test)]
fn encode_compliance_instance(instance: &ComplianceInstance) -> Vec<u8> {
    instance_to_journal(instance).expect("instance must serialize")
}

#[cfg(test)]
fn set_action_kind_table_commitment(action: &mut Action, commitment: Digest) {
    let mut instance: ComplianceInstance =
        journal_to_instance(&action.compliance_unit.instance).expect("instance must decode");
    instance.kind_table_commitment = commitment;
    action.compliance_unit.instance = encode_compliance_instance(&instance);
}

/// A 32-byte nonce that varies per index. The exact bytes don't matter as long
/// as nonces are distinct across consumed resources within a CU.
fn nonce_from_index(index: u32) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_exact_mut(4) {
        chunk.copy_from_slice(&index.to_be_bytes());
    }
    bytes
}

#[test]
fn test_logic_prover() {
    let test_logic = TestLogic::default();
    let proof = test_logic.prove(ProofType::Succinct).unwrap();
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
    // Swap logic verifier inputs to cause tag mismatch at position 0 in action0.
    let mut action0 = actions[0].clone();
    action0.logic_verifier_inputs = actions[1].logic_verifier_inputs.clone();
    assert!(action0.verify().is_err());

    // Empty logic verifier inputs: length mismatch must be rejected.
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

    // Introduce a duplicate nullifier by replacing action 1 with action 0.
    let action0 = tx.actions.as_ref().unwrap()[0].clone();
    tx.actions.as_mut().unwrap()[1] = action0;

    assert!(tx.nf_duplication_check().is_err());
}

/// All actions carry the global kind-table commitment — the check must pass.
#[test]
fn test_kind_table_commitment_check_accepts_global_commitment() {
    let tx = Tester::default()
        .generate_test_transaction(&[(1, 1)])
        .unwrap();
    assert!(tx.kind_table_commitment_check().is_ok());
}

/// One action has a different commitment from the other — cross-action
/// consistency check must fire before the global check.
#[test]
fn test_kind_table_commitment_check_rejects_mismatched_actions() {
    let mut tx = Tester::default()
        .generate_test_transaction(&[(1, 1), (1, 1)])
        .unwrap();

    set_action_kind_table_commitment(&mut tx.actions[1], Digest::from([0xA5; 32]));

    assert!(matches!(
        tx.kind_table_commitment_check(),
        Err(ArmError::KindTableCommitmentMismatch)
    ));
}

/// Both actions agree on a fake commitment — cross-action check passes but the
/// global check must catch the mismatch.
#[test]
fn test_kind_table_commitment_check_rejects_consistent_non_global() {
    let mut tx = Tester::default()
        .generate_test_transaction(&[(1, 1), (1, 1)])
        .unwrap();

    let fake = Digest::from([0x5A; 32]);
    set_action_kind_table_commitment(&mut tx.actions[0], fake);
    set_action_kind_table_commitment(&mut tx.actions[1], fake);

    assert!(matches!(
        tx.kind_table_commitment_check(),
        Err(ArmError::KindTableGlobalMismatch)
    ));
}

/// Single action with a non-global commitment — trivially passes cross-action
/// check, global check must reject.
#[test]
fn test_kind_table_commitment_check_rejects_global_mismatch() {
    let mut tx = Tester::default()
        .generate_test_transaction(&[(1, 1)])
        .unwrap();

    set_action_kind_table_commitment(&mut tx.actions[0], Digest::from([0x5A; 32]));

    assert!(matches!(
        tx.kind_table_commitment_check(),
        Err(ArmError::KindTableGlobalMismatch)
    ));
}

#[test]
fn test_aggregation_works() {
    let tx = Tester::default()
        .generate_test_transaction(&[(2, 2), (2, 2)])
        .unwrap();
    let mut tx_str = tx.clone();
    assert!(tx_str.aggregate(ProofType::Succinct).is_ok());
    // After aggregation: actions must be None, aggregation must be Some.
    assert!(tx_str.actions.is_none());
    assert!(tx_str.aggregation.is_some());
    assert!(tx_str.verify_aggregation().is_ok());
    // Full verify() must also succeed on the post-aggregation transaction.
    assert!(tx_str.verify().is_ok());
}

/// Same as `test_aggregation_works` but with a Groth16 outer aggregation
/// proof. Ignored because Groth16 proving is slow even in dev mode and
/// requires x86_64.
#[test]
#[ignore]
fn test_aggregation_works_groth16() {
    let tx = Tester::default()
        .generate_test_transaction(&[(2, 2), (2, 2)])
        .unwrap();
    let mut tx_str = tx.clone();
    assert!(tx_str.aggregate(ProofType::Groth16).is_ok());
    assert!(tx_str.actions.is_none());
    assert!(tx_str.aggregation.is_some());
    assert!(tx_str.verify_aggregation().is_ok());
}

#[test]
fn test_verify_aggregation_fails_for_tampered_instance() {
    use anoma_rm_risc0::{aggregation_instance::AggregationInstance, Digest};
    use anoma_rm_risc0::transaction::Aggregation;

    let mut tx = Tester::default()
        .generate_test_transaction(&[(2, 2), (2, 2)])
        .unwrap();

    // Inject a fake Aggregation with a garbage proof and a tampered instance.
    // verify_aggregation() must reject it without needing the new ELF.
    let fake_instance = AggregationInstance {
        compliance_key: Digest::from([0xFFu8; 32]),
        kind_table_commitment: Digest::default(),
        actions: vec![],
    };
    tx.aggregation = Some(Aggregation {
        proof: vec![0u8; 64],
        instance: fake_instance,
    });

    assert!(tx.verify_aggregation().is_err());
}

/// A balanced action with no created resources (1 ephemeral consumed, 0
/// created). Per-action verification only checks the unit + logic proofs;
/// balance is enforced at the transaction level.
#[test]
fn test_action_with_zero_created() {
    let action = Tester::default().create_an_action(1, 0).unwrap();
    assert!(action.verify().is_ok());
}

/// `Tester` defaults consume same-kind resources, so summing 2 consumed and 2
/// created of quantity 1 each must net to zero in the delta — covering the
/// per-kind aggregation path inside `constrain_delta`.
#[test]
fn test_compliance_unit_balanced_same_kind() {
    let unit = Tester::default().create_compliance_unit(2, 2).unwrap();
    assert!(unit.verify().is_ok());
}

/// Composing two balanced witness-form transactions yields a balanced
/// transaction once its delta proof is generated.
#[test]
fn test_compose_transactions() {
    let mut tester_a = Tester::default();
    let actions_a = tester_a.create_multiple_actions(&[(1, 1)]).unwrap();
    let tx_a = Transaction::create(actions_a, Delta::Witness(tester_a.delta_witness()));

    let mut tester_b = Tester::default();
    let actions_b = tester_b.create_multiple_actions(&[(2, 2)]).unwrap();
    let tx_b = Transaction::create(actions_b, Delta::Witness(tester_b.delta_witness()));

    let composed = Transaction::compose(tx_a, tx_b)
        .unwrap()
        .generate_delta_proof()
        .unwrap();
    assert!(composed.verify().is_ok());
}

/// Aggregating a transaction where one logic verifier has a bad verifying key
/// must fail; the aggregation proof must remain absent.
#[test]
fn test_cannot_aggregate_invalid_proofs() {
    use anoma_rm_risc0::logic_proof::LogicVerifierInputs;

    let tx = Tester::default()
        .generate_test_transaction(&[(2, 2), (2, 2)])
        .unwrap();

    let actions = tx.actions.as_ref().unwrap();
    let bad_lproof = LogicVerifierInputs {
        proof: actions[0].logic_verifier_inputs[0].proof.clone(),
        verifying_key: Digest::from([66u8; 32]),
        tag: actions[0].logic_verifier_inputs[0].tag,
        app_data: actions[0].logic_verifier_inputs[0].app_data.clone(),
    };

    let bad_action = Action {
        compliance_unit: actions[0].compliance_unit.clone(),
        logic_verifier_inputs: vec![bad_lproof],
    };
    let bad_tx = Transaction::create(vec![bad_action, actions[1].clone()], tx.delta_proof);

    let mut bad_tx_str = bad_tx.clone();
    assert!(bad_tx_str.aggregate(ProofType::Succinct).is_err());
    assert!(bad_tx_str.aggregation.is_none());
}

/// Constructing a compliance witness with a wrong created-resource nonce must
/// be rejected by `constrain` with `InvalidResourceNonce`.
#[test]
fn test_invalid_created_nonce_rejected() {
    let mut tester = Tester::default();
    tester.populate_consumed_resources(1);
    tester.populate_created_resources(1).unwrap();
    tester.set_created_nonce(0, 0, [0xAA; 32]);

    init_test_kind_table();
    let witness = ComplianceWitness::from_resources(
        &tester.consumed_data[0],
        &tester.created_resources[0],
        global_kind_table().to_vec(),
    );

    assert!(matches!(
        witness.constrain(),
        Err(ArmError::InvalidResourceNonce)
    ));
}
