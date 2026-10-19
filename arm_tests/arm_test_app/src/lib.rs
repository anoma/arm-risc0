// This module contains a trivial test circuit and tx tests for the ARM crate.
// The functions here are also used in the elixir sdk and binding libraries to
// ensure that the ARM crate's transaction functionalities work as expected.

use anoma_rm_risc0::{
    action::{self, Action},
    action_tree::ActionTree,
    compliance,
    compliance_unit::{self, ComplianceUnit},
    constants::{global_kind_tree, init_starter_kind_tree},
    delta_proof::{self, DeltaWitness},
    error::ArmError,
    logic_proof::{LogicProver, LogicVerifier},
    merkle_path::MerklePath,
    nullifier_key::{self, NullifierKey},
    proving_system::ProofType,
    resource::{ConsumedResourceWitness, Resource, ResourceWitness},
    transaction::{self, Delta, Transaction},
    Digest,
};
#[cfg(test)]
use anoma_rm_risc0::{
    compliance::ComplianceInstance,
    constants::kind_tree_root,
    logic_proof,
    proving_system::{instance_to_journal, journal_to_instance, JournalEncoding},
};
use anoma_rm_risc0_test_witness::TestLogicWitness;
use hex::FromHex;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

// Test logic proving key / test logic guest ELF binary
pub const TEST_LOGIC_PK: &[u8] = include_bytes!("../elf/logic-test-guest.bin");

lazy_static! {
    // test logic verification key / test image id
    pub static ref TEST_LOGIC_VK: Digest =
        Digest::from_hex("2f494b55a99e5bc790cc416edbfc08974b0056cfb4ab5fef3b5b49fdeec6ce3e")
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
        let (nf_key, nk_commitment) = nullifier_key::random_pair();
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
        let order = consumed_first(consumed_num, created_num);
        let (compliance_unit, _) =
            self.create_compliance_unit_in_order(consumed_num, created_num, &order)?;
        Ok(compliance_unit)
    }

    /// Creates a compliance unit for the current action with its resources in
    /// `order`, and returns it with its resources in this order.
    fn create_compliance_unit_in_order(
        &mut self,
        consumed_num: u32,
        created_num: u32,
        order: &[usize],
    ) -> Result<(ComplianceUnit, Vec<ResourceWitness>), ArmError> {
        self.populate_consumed_resources(consumed_num);
        self.populate_created_resources(created_num)?;
        let resources = self.resources_in_order(order)?;

        init_test_kind_tree();
        let compliance_witness = compliance::from_resources(
            resources.clone(),
            global_kind_tree().expect("kind tree not initialised"),
        );
        self.rcvs.push(compliance_witness.rcv.clone());

        let compliance_unit = compliance_unit::create(&compliance_witness, ProofType::Succinct)?;
        Ok((compliance_unit, resources))
    }

    /// Lists the resources of the current action in `order`: positions in the
    /// list of its consumed, then its created resources. The nonces of the
    /// created resources are derived again for this order.
    fn resources_in_order(&mut self, order: &[usize]) -> Result<Vec<ResourceWitness>, ArmError> {
        let consumed = &self.consumed_data[self.current];
        let created = &mut self.created_resources[self.current];
        let n_consumed = consumed.len();

        let nullifiers = order
            .iter()
            .filter(|&&i| i < n_consumed)
            .map(|&i| consumed[i].resource.nullifier(&consumed[i].nf_key))
            .collect::<Result<Vec<Digest>, _>>()?;
        let nullifiers_digest = Resource::hash_nullifiers(&nullifiers)?;
        for (index, &i) in order.iter().filter(|&&i| i >= n_consumed).enumerate() {
            created[i - n_consumed].nonce = Resource::derive_nonce(index as u32, nullifiers_digest);
        }

        Ok(order
            .iter()
            .map(|&i| match i.checked_sub(n_consumed) {
                None => ResourceWitness::Consumed(consumed[i].clone()),
                Some(k) => ResourceWitness::Created(created[k]),
            })
            .collect())
    }

    /// Creates an action with `consumed_num` consumed and `created_num` created resources.
    pub fn create_an_action(
        &mut self,
        consumed_num: u32,
        created_num: u32,
    ) -> Result<Action, ArmError> {
        let order = consumed_first(consumed_num, created_num);
        self.create_an_action_in_order(consumed_num, created_num, &order)
    }

    /// Creates an action whose compliance unit lists the resources in `order`:
    /// positions in the list of the consumed, then the created resources.
    pub fn create_an_action_in_order(
        &mut self,
        consumed_num: u32,
        created_num: u32,
        order: &[usize],
    ) -> Result<Action, ArmError> {
        let (compliance_unit, resources) =
            self.create_compliance_unit_in_order(consumed_num, created_num, order)?;
        let tags = compliance_unit::get_instance(&compliance_unit)?
            .tags()
            .collect();
        let logic_verifiers = prove_logics(&resources, &ActionTree::new(tags));

        let action = action::new(compliance_unit, logic_verifiers)?;
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
        transaction::generate_delta_proof(Transaction::create(
            actions,
            Delta::Witness(self.delta_witness()),
        ))
    }

    /// Builds a `DeltaWitness` from the per-CU randomness collected so far.
    /// Use this rather than reaching into the `rcvs` field directly.
    pub fn delta_witness(&self) -> DeltaWitness {
        delta_proof::from_bytes_vec(&self.rcvs).unwrap()
    }

    /// Test-only escape hatch: overwrites the nonce of an already-populated
    /// created resource. Reaching into `created_resources` directly is
    /// possible but couples the test to an internal layout that may change.
    pub fn set_created_nonce(&mut self, action_idx: usize, resource_idx: usize, nonce: [u8; 32]) {
        self.created_resources[action_idx][resource_idx].nonce = nonce;
    }
}

fn init_test_kind_tree() {
    init_starter_kind_tree().expect("Failed to load arm's starter kind tree");
}

/// The positions of all consumed resources, then all created resources.
fn consumed_first(consumed_num: u32, created_num: u32) -> Vec<usize> {
    (0..(consumed_num + created_num) as usize).collect()
}

/// Proves the test logic of each resource, in the order of `resources`,
/// against the root of `action_tree`.
fn prove_logics(resources: &[ResourceWitness], action_tree: &ActionTree) -> Vec<LogicVerifier> {
    resources
        .iter()
        .map(|resource_witness| {
            let (tag, nf_key, is_consumed) = match resource_witness {
                ResourceWitness::Consumed(w) => (
                    w.resource.nullifier(&w.nf_key).unwrap(),
                    w.nf_key.clone(),
                    true,
                ),
                ResourceWitness::Created(resource) => {
                    (resource.commitment(), NullifierKey::default(), false)
                }
            };
            let action_tree_path = action_tree.generate_path(&tag).unwrap();
            TestLogic::new(
                *resource_witness.resource(),
                action_tree_path,
                nf_key,
                is_consumed,
            )
            .prove(ProofType::Succinct)
            .unwrap()
        })
        .collect()
}

#[cfg(test)]
fn encode_compliance_instance(instance: &ComplianceInstance) -> Vec<u8> {
    instance_to_journal(instance).expect("instance must serialize")
}

#[cfg(test)]
fn set_action_kind_tree_root(action: &mut Action, root: Digest) {
    let mut instance: ComplianceInstance =
        journal_to_instance(&action.compliance_unit.instance).expect("instance must decode");
    instance.kind_tree_root = root;
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
    logic_proof::verify(&proof).unwrap();
}

#[test]
fn test_compliance_unit() {
    let compliance_unit = Tester::default().create_compliance_unit(3, 2).unwrap();
    assert!(compliance_unit::verify(&compliance_unit).is_ok())
}

#[test]
fn test_compliance_unit_must_consume_resources() {
    let compliance_unit = Tester::default().create_compliance_unit(0, 1);
    assert!(compliance_unit.is_err())
}

#[test]
fn test_action() {
    let action = Tester::default().create_an_action(3, 2).unwrap();
    assert!(action::verify(&action).is_ok())
}

#[test]
fn test_transaction() {
    let balanced_tx = Tester::default()
        .generate_test_transaction(&[(2, 1), (1, 2)])
        .unwrap();
    assert!(transaction::verify(
        &balanced_tx,
        kind_tree_root().unwrap(),
        JournalEncoding::Risc0Serde
    )
    .is_ok())
}

#[test]
fn test_unbalanced_tx_fails_to_verify() {
    let unbalanced_tx = Tester::default()
        .generate_test_transaction(&[(2, 1), (1, 1)])
        .unwrap();
    assert!(transaction::verify(
        &unbalanced_tx,
        kind_tree_root().unwrap(),
        JournalEncoding::Risc0Serde
    )
    .is_err())
}

#[test]
fn test_unmatched_logic_verifier_inputs_in_action() {
    let actions = Tester::default()
        .create_multiple_actions(&[(1, 1), (1, 1)])
        .unwrap();
    // Swap logic verifier inputs to cause tag mismatch at position 0 in action0.
    let mut action0 = actions[0].clone();
    action0.logic_verifier_inputs = actions[1].logic_verifier_inputs.clone();
    assert!(action::verify(&action0).is_err());

    // Empty logic verifier inputs: length mismatch must be rejected.
    let mut action1 = actions[1].clone();
    action1.logic_verifier_inputs = vec![];
    assert!(action::verify(&action1).is_err());
}

#[test]
fn test_logic_verifier_input_with_wrong_verifying_key_rejected() {
    // A logic verifier input whose tag and position are correct but whose
    // `verifying_key` does not match the resource's declared `resource_logic_ref`
    // must be rejected, even before any proof is checked. Without this check a
    // proof for an unrelated logic circuit could be substituted for the
    // resource's real logic.
    let actions = Tester::default()
        .create_multiple_actions(&[(1, 1)])
        .unwrap();
    let mut action = actions[0].clone();
    action.logic_verifier_inputs[0].verifying_key = Digest::default();
    assert_eq!(action::verify(&action), Err(ArmError::VerifyingKeyMismatch));
}

#[test]
fn test_nullifier_duplication_check() {
    let mut tx = Tester::default()
        .generate_test_transaction(&[(1, 1), (1, 1)])
        .unwrap();
    assert!(transaction::nf_duplication_check(&tx).is_ok());

    // Introduce a duplicate nullifier by replacing action 1 with action 0.
    let action0 = tx.actions.as_ref().unwrap()[0].clone();
    tx.actions.as_mut().unwrap()[1] = action0;

    assert!(transaction::nf_duplication_check(&tx).is_err());
}

/// All actions carry the global kind-tree root — the check must pass.
#[test]
fn test_kind_tree_root_check_accepts_global_root() {
    let tx = Tester::default()
        .generate_test_transaction(&[(1, 1)])
        .unwrap();
    assert!(transaction::kind_tree_root_check(&tx, kind_tree_root().unwrap()).is_ok());
}

/// All actions carry a non-global root and the caller supplies that same
/// digest as `expected` — the check must succeed. This guards against a
/// regression back to an implicit global-tree lookup.
#[test]
fn test_kind_tree_root_check_accepts_explicit_non_global_root() {
    let mut tx = Tester::default()
        .generate_test_transaction(&[(1, 1), (1, 1)])
        .unwrap();

    let fake = Digest::from([0xAB; 32]);
    let actions = tx.actions.as_mut().unwrap();
    set_action_kind_tree_root(&mut actions[0], fake);
    set_action_kind_tree_root(&mut actions[1], fake);

    assert!(transaction::kind_tree_root_check(&tx, fake).is_ok());
}

/// One action has a different root from the other — cross-action
/// consistency check must fire before the global check.
#[test]
fn test_kind_tree_root_check_rejects_mismatched_actions() {
    let mut tx = Tester::default()
        .generate_test_transaction(&[(1, 1), (1, 1)])
        .unwrap();

    set_action_kind_tree_root(
        &mut tx.actions.as_mut().unwrap()[1],
        Digest::from([0xA5; 32]),
    );

    assert!(matches!(
        transaction::kind_tree_root_check(&tx, kind_tree_root().unwrap()),
        Err(ArmError::KindTreeRootMismatch)
    ));
}

/// Both actions agree on a fake root — cross-action check passes but the
/// global check must catch the mismatch. Also asserts that passing the fake
/// root explicitly succeeds, covering the multi-chain case.
#[test]
fn test_kind_tree_root_check_rejects_consistent_non_global() {
    let mut tx = Tester::default()
        .generate_test_transaction(&[(1, 1), (1, 1)])
        .unwrap();

    let fake = Digest::from([0x5A; 32]);
    let actions = tx.actions.as_mut().unwrap();
    set_action_kind_tree_root(&mut actions[0], fake);
    set_action_kind_tree_root(&mut actions[1], fake);

    // Caller-provided root matching the tx must succeed.
    assert!(transaction::kind_tree_root_check(&tx, fake).is_ok());

    // Passing a different (global) root must be rejected.
    assert!(matches!(
        transaction::kind_tree_root_check(&tx, kind_tree_root().unwrap()),
        Err(ArmError::KindTreeRootExpectedMismatch)
    ));
}

/// Single action with a non-global root — trivially passes cross-action
/// check, global check must reject.
#[test]
fn test_kind_tree_root_check_rejects_global_mismatch() {
    let mut tx = Tester::default()
        .generate_test_transaction(&[(1, 1)])
        .unwrap();

    set_action_kind_tree_root(
        &mut tx.actions.as_mut().unwrap()[0],
        Digest::from([0x5A; 32]),
    );

    assert!(matches!(
        transaction::kind_tree_root_check(&tx, kind_tree_root().unwrap()),
        Err(ArmError::KindTreeRootExpectedMismatch)
    ));
}

#[test]
fn test_aggregation_works() {
    let tx = Tester::default()
        .generate_test_transaction(&[(2, 2), (2, 2)])
        .unwrap();
    let mut tx_str = tx.clone();
    assert!(transaction::aggregate(
        &mut tx_str,
        ProofType::Succinct,
        JournalEncoding::Risc0Serde
    )
    .is_ok());
    // After aggregation: actions must be None, aggregation must be Some.
    assert!(tx_str.actions.is_none());
    assert!(tx_str.aggregation.is_some());
    assert!(transaction::verify_aggregation(&tx_str, JournalEncoding::Risc0Serde).is_ok());
    // Full verify() must also succeed on the post-aggregation transaction.
    assert!(transaction::verify(
        &tx_str,
        kind_tree_root().unwrap(),
        JournalEncoding::Risc0Serde
    )
    .is_ok());

    // Tamper the compliance_key in the decoded instance — the receipt is still
    // valid against BATCH_AGGREGATION_VK, but the compliance_key check must
    // now catch the mismatch before the verifier accepts the proof.
    if let Some(ref mut agg) = tx_str.aggregation {
        agg.instance.compliance_key = Digest::from([0xABu8; 32]);
    }
    assert!(transaction::verify_aggregation(&tx_str, JournalEncoding::Risc0Serde).is_err());
}

/// `aggregation_witness` builds the guest's input under the compliance key the
/// caller names: one action witness per action, each carrying its resources'
/// app data in the order of the compliance unit.
#[test]
fn test_aggregation_witness_takes_the_callers_compliance_key() {
    use risc0_zkvm::ExecutorEnv;

    let tx = Tester::default()
        .generate_test_transaction(&[(2, 2), (1, 1)])
        .unwrap();
    let actions = tx.actions.as_ref().unwrap();
    let key = Digest::from([0xCDu8; 32]);

    let witness =
        transaction::aggregation_witness(actions, key, &mut ExecutorEnv::builder()).unwrap();
    assert_eq!(witness.compliance_key, key);
    assert_eq!(witness.actions.len(), actions.len());
    for (action, action_witness) in actions.iter().zip(&witness.actions) {
        let app_data: Vec<_> = action
            .logic_verifier_inputs
            .iter()
            .map(|lvi| lvi.app_data.clone())
            .collect();
        assert_eq!(action_witness.app_data, app_data);
    }

    // A consumed resource's logic input swapped with a created one's.
    let mut swapped = actions.clone();
    swapped[0].logic_verifier_inputs.swap(0, 2);
    // The error names the action, the position, and both tags.
    let err = transaction::aggregation_witness(&swapped, key, &mut ExecutorEnv::builder())
        .err()
        .expect("swapped logic inputs must be rejected");
    let ArmError::InAction { action, source } = err else {
        panic!("expected the error to name its action, got {err:?}");
    };
    assert_eq!(action, 0);
    assert!(
        matches!(
            *source,
            ArmError::LogicVerifierTagMismatch {
                position: 0,
                expected,
                found,
            } if expected != found
        ),
        "expected a located tag mismatch, got {source:?}"
    );
}

/// The compliance instance lists the resources in the order of the witness,
/// and the nonce of a created resource counts only the created resources.
#[test]
fn test_compliance_instance_follows_the_order_of_the_witness() {
    let mut tester = Tester::default();
    tester.populate_consumed_resources(2);
    tester.populate_created_resources(2).unwrap();
    // The first created resource ahead of both consumed ones: the second
    // created resource is at position 3 but has the created index 1.
    let resources = tester.resources_in_order(&[2, 0, 1, 3]).unwrap();

    init_test_kind_tree();
    let witness = compliance::from_resources(
        resources.clone(),
        global_kind_tree().expect("kind tree not initialised"),
    );
    let instance = compliance::constrain(&witness).unwrap();

    let tags: Vec<Digest> = resources
        .iter()
        .map(|r| match r {
            ResourceWitness::Consumed(w) => w.resource.nullifier(&w.nf_key).unwrap(),
            ResourceWitness::Created(resource) => resource.commitment(),
        })
        .collect();
    assert_eq!(instance.tags().collect::<Vec<_>>(), tags);
    let is_consumed: Vec<bool> = instance
        .resource_publics
        .iter()
        .map(|r| r.is_consumed())
        .collect();
    assert_eq!(is_consumed, [false, true, true, false]);
}

/// The nonce of a created resource derives from its index among the created
/// resources and from the consumed nullifiers in their order, so a witness
/// with two swapped resources of one kind is refused.
#[test]
fn test_constrain_rejects_resources_in_another_order_than_their_nonces() {
    let mut tester = Tester::default();
    tester.populate_consumed_resources(2);
    tester.populate_created_resources(2).unwrap();
    let resources = tester.resources_in_order(&[0, 1, 2, 3]).unwrap();

    init_test_kind_tree();
    let kind_tree = global_kind_tree().expect("kind tree not initialised");
    let constrain_in_order = |order: [usize; 4]| {
        let resources = order.map(|i| resources[i].clone()).to_vec();
        compliance::constrain(&compliance::from_resources(resources, kind_tree))
    };

    assert!(
        constrain_in_order([0, 1, 2, 3]).is_ok(),
        "the resources in the order of their nonces are accepted"
    );
    assert!(matches!(
        constrain_in_order([0, 1, 3, 2]),
        Err(ArmError::InvalidResourceNonce)
    ));
    assert!(matches!(
        constrain_in_order([1, 0, 2, 3]),
        Err(ArmError::InvalidResourceNonce)
    ));
}

/// The aggregation instance lists an action's resources in the order of its
/// compliance unit, the action tree root covers this order, and a created
/// resource carries no commitment tree root.
#[test]
fn test_aggregation_follows_the_order_of_the_compliance_unit() {
    let mut tester = Tester::default();
    // The first created resource ahead of both consumed ones, which swap places.
    let action = tester
        .create_an_action_in_order(2, 2, &[2, 1, 0, 3])
        .unwrap();
    let tags: Vec<Digest> = compliance_unit::get_instance(&action.compliance_unit)
        .unwrap()
        .tags()
        .collect();
    let mut tx = transaction::generate_delta_proof(Transaction::create(
        vec![action],
        Delta::Witness(tester.delta_witness()),
    ))
    .unwrap();

    transaction::aggregate(&mut tx, ProofType::Succinct, JournalEncoding::Risc0Serde).unwrap();
    assert!(transaction::verify_aggregation(&tx, JournalEncoding::Risc0Serde).is_ok());

    let action = &tx.aggregation.as_ref().unwrap().instance.actions[0];
    let aggregated_tags: Vec<Digest> = action
        .resource_publics
        .iter()
        .map(|r| r.resource_tag)
        .collect();
    assert_eq!(aggregated_tags, tags);
    assert_eq!(
        action.action_tree_root,
        ActionTree::new(tags).root().unwrap()
    );
    let is_consumed: Vec<bool> = action
        .resource_publics
        .iter()
        .map(|r| r.is_consumed())
        .collect();
    assert_eq!(is_consumed, [false, true, true, false]);
}

/// The logic proofs commit to the action tree root, which covers the order of
/// the compliance unit, so logic proofs for another order do not verify.
#[test]
fn test_aggregation_rejects_logic_proofs_for_another_order_than_the_compliance_unit() {
    let mut tester = Tester::default();
    let (compliance_unit, resources) = tester
        .create_compliance_unit_in_order(2, 2, &consumed_first(2, 2))
        .unwrap();
    let tags: Vec<Digest> = compliance_unit::get_instance(&compliance_unit)
        .unwrap()
        .tags()
        .collect();

    let action = action::new(
        compliance_unit.clone(),
        prove_logics(&resources, &ActionTree::new(tags.clone())),
    )
    .unwrap();
    assert!(
        action::verify(&action).is_ok(),
        "logic proofs for the order of the unit verify"
    );

    let other_order = vec![tags[2], tags[1], tags[0], tags[3]];
    let action = action::new(
        compliance_unit,
        prove_logics(&resources, &ActionTree::new(other_order)),
    )
    .unwrap();
    assert!(action::verify(&action).is_err());

    let mut tx = transaction::generate_delta_proof(Transaction::create(
        vec![action],
        Delta::Witness(tester.delta_witness()),
    ))
    .unwrap();
    assert!(
        transaction::aggregate(&mut tx, ProofType::Succinct, JournalEncoding::Risc0Serde).is_err()
    );
}

/// After aggregation, the decoded `AggregationInstance` survives a round-trip
/// through `AggregationInstanceEvm` and matches structural expectations.
#[test]
fn test_evm_instance_roundtrip_after_aggregation() {
    use anoma_rm_risc0::aggregation_instance::{abi_encode_instance, AggregationInstanceEvm};

    let tx = Tester::default()
        .generate_test_transaction(&[(2, 2), (1, 1)])
        .unwrap();
    let mut tx_str = tx.clone();
    transaction::aggregate(&mut tx_str, ProofType::Succinct, JournalEncoding::Abi).unwrap();

    let instance = tx_str.aggregation.as_ref().unwrap().instance.clone();

    // Native → EVM → Native round-trip must be lossless.
    let evm = AggregationInstanceEvm::from(instance.clone());
    let recovered = anoma_rm_risc0::aggregation_instance::AggregationInstance::from(evm);
    assert_eq!(instance, recovered);

    // ABI encode/decode round-trip via abi_encode_instance must also be lossless.
    let encoded = abi_encode_instance(instance.clone());
    let recovered2 = anoma_rm_risc0::aggregation_instance::abi_decode_instance(&encoded).unwrap();
    assert_eq!(instance, recovered2);

    // Structural sanity: two actions, first has 2 consumed + 2 created, second 1 + 1.
    assert_eq!(instance.actions.len(), 2);
    let is_consumed = |action: usize| -> Vec<bool> {
        instance.actions[action]
            .resource_publics
            .iter()
            .map(|r| r.is_consumed())
            .collect()
    };
    assert_eq!(is_consumed(0), [true, true, false, false]);
    assert_eq!(is_consumed(1), [true, false]);
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
    assert!(
        transaction::aggregate(&mut tx_str, ProofType::Groth16, JournalEncoding::Risc0Serde)
            .is_ok()
    );
    assert!(tx_str.actions.is_none());
    assert!(tx_str.aggregation.is_some());
    assert!(transaction::verify_aggregation(&tx_str, JournalEncoding::Risc0Serde).is_ok());
}

#[test]
fn test_verify_aggregation_fails_for_tampered_instance() {
    use anoma_rm_risc0::{aggregation_instance::AggregationInstance, Digest};
    use transaction::Aggregation;

    let mut tx = Tester::default()
        .generate_test_transaction(&[(2, 2), (2, 2)])
        .unwrap();

    // Inject a fake Aggregation with a garbage proof and a tampered instance.
    // verify_aggregation() must reject it without needing the new ELF.
    let fake_instance = AggregationInstance {
        compliance_key: Digest::from([0xFFu8; 32]),
        kind_tree_root: Digest::default(),
        actions: vec![],
    };
    tx.aggregation = Some(Aggregation {
        proof: vec![0u8; 64],
        instance: fake_instance,
    });

    assert!(transaction::verify_aggregation(&tx, JournalEncoding::Risc0Serde).is_err());
}

#[test]
fn test_verify_rejects_transaction_with_both_actions_and_aggregation() {
    use anoma_rm_risc0::{aggregation_instance::AggregationInstance, Digest};
    use transaction::Aggregation;

    // `Transaction` is a plain deserializable struct, so nothing stops a
    // crafted instance from carrying both `actions` (unverified, real
    // delta proof attached) and an unrelated `aggregation`. Before the fix,
    // `verify()` derived the delta message / instance / nullifier set from
    // `actions` but only cryptographically verified `aggregation` — so the
    // unverified `actions` state was silently accepted as long as *some*
    // aggregation proof (valid or not, related or not) was attached. The
    // guard must reject this purely on shape, before any proof is checked
    // — which is why a garbage aggregation is sufficient to prove the fix.
    let mut tx = Tester::default()
        .generate_test_transaction(&[(1, 1)])
        .unwrap();
    assert!(tx.actions.is_some());

    tx.aggregation = Some(Aggregation {
        proof: vec![0u8; 64],
        instance: AggregationInstance {
            compliance_key: Digest::default(),
            kind_tree_root: Digest::default(),
            actions: vec![],
        },
    });

    assert_eq!(
        tx.check_representation(),
        Err(ArmError::AmbiguousTransactionRepresentation)
    );
    assert_eq!(
        transaction::verify(&tx, Digest::from([0u8; 32]), JournalEncoding::Risc0Serde),
        Err(ArmError::AmbiguousTransactionRepresentation)
    );
}

/// A balanced action with no created resources (1 ephemeral consumed, 0
/// created). Per-action verification only checks the unit + logic proofs;
/// balance is enforced at the transaction level.
#[test]
fn test_action_with_zero_created() {
    let action = Tester::default().create_an_action(1, 0).unwrap();
    assert!(action::verify(&action).is_ok());
}

/// `Tester` defaults consume same-kind resources, so summing 2 consumed and 2
/// created of quantity 1 each must net to zero in the delta — covering the
/// per-kind aggregation path inside `constrain_delta`.
#[test]
fn test_compliance_unit_balanced_same_kind() {
    let unit = Tester::default().create_compliance_unit(2, 2).unwrap();
    assert!(compliance_unit::verify(&unit).is_ok());
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

    let composed =
        transaction::generate_delta_proof(transaction::compose(tx_a, tx_b).unwrap()).unwrap();
    assert!(transaction::verify(
        &composed,
        kind_tree_root().unwrap(),
        JournalEncoding::Risc0Serde
    )
    .is_ok());
}

/// `compose()` must reject any input that carries both `actions` and
/// `aggregation` (the ambiguous "both present" shape).
///
/// This test deliberately avoids proof generation — the guard fires before any
/// cryptographic work, so dummy delta witnesses and empty action vecs suffice.
#[test]
fn test_compose_rejects_ambiguous_transaction() {
    use anoma_rm_risc0::{aggregation_instance::AggregationInstance, Digest};
    use transaction::Aggregation;

    let dummy_delta = || Delta::Witness(delta_proof::from_bytes_vec(&[vec![1u8; 32]]).unwrap());

    // A well-formed transaction (actions present, no aggregation).
    let tx_clean = Transaction::create(vec![], dummy_delta());

    // A crafted transaction with both fields set — the ambiguous shape.
    let mut tx_ambiguous = Transaction::create(vec![], dummy_delta());
    tx_ambiguous.aggregation = Some(Aggregation {
        proof: vec![0u8; 64],
        instance: AggregationInstance {
            compliance_key: Digest::from([0xFFu8; 32]),
            kind_tree_root: Digest::default(),
            actions: vec![],
        },
    });

    // compose() propagates the representation error as raised, rather than
    // relabelling the ambiguous shape as "cannot compose aggregated".
    assert_eq!(
        transaction::compose(tx_ambiguous.clone(), tx_clean.clone()),
        Err(ArmError::AmbiguousTransactionRepresentation),
    );
    assert_eq!(
        transaction::compose(tx_clean, tx_ambiguous),
        Err(ArmError::AmbiguousTransactionRepresentation),
    );
}

/// Aggregating a transaction where one logic verifier has a bad verifying key
/// must fail; the aggregation proof must remain absent.
#[test]
fn test_cannot_aggregate_invalid_proofs() {
    use anoma_rm_risc0::logic_proof::LogicVerifierInput;

    let tx = Tester::default()
        .generate_test_transaction(&[(2, 2), (2, 2)])
        .unwrap();

    let actions = tx.actions.as_ref().unwrap();
    let bad_lproof = LogicVerifierInput {
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
    assert!(transaction::aggregate(
        &mut bad_tx_str,
        ProofType::Succinct,
        JournalEncoding::Risc0Serde
    )
    .is_err());
    assert!(bad_tx_str.aggregation.is_none());
}

/// aggregate() on a transaction with an empty actions vec must fail gracefully
/// rather than panicking inside the guest.
#[test]
fn test_cannot_aggregate_empty_actions() {
    let dummy_delta = Delta::Witness(delta_proof::from_bytes_vec(&[vec![1u8; 32]]).unwrap());
    let mut tx =
        transaction::generate_delta_proof(Transaction::create(vec![], dummy_delta)).unwrap();
    let result = transaction::aggregate(&mut tx, ProofType::Succinct, JournalEncoding::Risc0Serde);
    assert!(result.is_err());
    assert!(tx.aggregation.is_none());
}

/// Constructing a compliance witness with a wrong created-resource nonce must
/// be rejected by `constrain` with `InvalidResourceNonce`.
#[test]
fn test_invalid_created_nonce_rejected() {
    let mut tester = Tester::default();
    tester.populate_consumed_resources(1);
    tester.populate_created_resources(1).unwrap();
    tester.set_created_nonce(0, 0, [0xAA; 32]);

    init_test_kind_tree();
    let resources = tester.consumed_data[0]
        .iter()
        .cloned()
        .map(ResourceWitness::Consumed)
        .chain(
            tester.created_resources[0]
                .iter()
                .copied()
                .map(ResourceWitness::Created),
        )
        .collect();
    let witness = compliance::from_resources(
        resources,
        global_kind_tree().expect("kind tree not initialised"),
    );

    assert!(matches!(
        compliance::constrain(&witness),
        Err(ArmError::InvalidResourceNonce)
    ));
}
