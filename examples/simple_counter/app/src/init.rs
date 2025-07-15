use crate::{
    convert_counter_to_value_ref, generate_compliance_proof, generate_logic_proofs, CounterLogic,
};
use arm::{
    action::Action,
    delta_proof::DeltaWitness,
    logic_proof::LogicProver,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    transaction::{Delta, Transaction},
};
use rand::Rng;

// It creates a random label reference and a nullifier key for the
// ephermeral counter resource.
pub fn ephemeral_counter() -> (Resource, NullifierKey) {
    let mut rng = rand::thread_rng();
    let (nf_key, nf_key_cm) = NullifierKey::random_pair();
    let label_ref: [u8; 32] = rng.gen(); // Random label reference, it should be unique for each counter
    let nonce: [u8; 32] = rng.gen(); // Random nonce for the ephemeral resource
    let ephemeral_resource = Resource::create(
        CounterLogic::verifying_key_as_bytes(),
        label_ref.to_vec(),
        1,
        convert_counter_to_value_ref(0u128), // Initialize with value/counter 0
        true,
        nonce.to_vec(),
        nf_key_cm,
    );
    (ephemeral_resource, nf_key)
}

// This function initializes a counter resource from an ephemeral counter
// resource and its nullifier key. It sets the resource as non-ephemeral, renews
// its randomness, resets the nonce from the ephemeral counter, and sets the
// value reference to 1 (the initial counter value). It also renews the
// nullifier key(commitment) for the counter resource.
pub fn init_counter_resource(
    ephemeral_counter: &Resource,
    ephemeral_counter_nf_key: &NullifierKey,
) -> (Resource, NullifierKey) {
    let (nf_key, nf_key_cm) = NullifierKey::random_pair();
    let mut init_counter = ephemeral_counter.clone();
    init_counter.is_ephemeral = false;
    init_counter.reset_randomness();
    init_counter.set_nonce_from_nf(ephemeral_counter, ephemeral_counter_nf_key);
    init_counter.set_value_ref(convert_counter_to_value_ref(1u128));
    init_counter.set_nf_commitment(nf_key_cm.clone());
    (init_counter, nf_key)
}

// This function creates an initial transaction that initializes a counter
// resource. It generates a compliance proof and logic proofs, and constructs
// the transaction. The transaction is then returned along with the counter
// resource and nullifier key.
pub fn create_init_counter_tx() -> (Transaction, Resource, NullifierKey) {
    let (ephemeral_counter, ephemeral_nf_key) = ephemeral_counter();
    let (counter_resource, counter_nf_key) =
        init_counter_resource(&ephemeral_counter, &ephemeral_nf_key);
    let (compliance_unit, rcv) = generate_compliance_proof(
        ephemeral_counter.clone(),
        ephemeral_nf_key.clone(),
        MerklePath::default(),
        counter_resource.clone(),
    );
    let logic_verifier_inputs = generate_logic_proofs(
        ephemeral_counter,
        ephemeral_nf_key,
        counter_resource.clone(),
    );

    let action = Action::new(vec![compliance_unit], logic_verifier_inputs, vec![]);
    let delta_witness = DeltaWitness::from_bytes(&rcv);
    let mut tx = Transaction::create(vec![action], Delta::Witness(delta_witness));
    tx.generate_delta_proof();
    (tx, counter_resource, counter_nf_key)
}

#[test]
fn test_create_init_counter_tx() {
    let (tx, counter_resource, _nf_key) = create_init_counter_tx();
    assert!(tx.verify(), "Transaction verification failed");
    let expected_value_ref = convert_counter_to_value_ref(1u128);
    assert_eq!(
        counter_resource.value_ref, expected_value_ref,
        "Counter resource value should be 1"
    );
}
