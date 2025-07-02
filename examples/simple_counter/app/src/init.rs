use crate::{
    convert_counter_to_value_ref, counter_logic_ref, generate_compliance_proof,
    generate_logic_proofs,
};
use arm::{
    action::Action,
    transaction::{Delta, Transaction},
};
use arm_core::{
    delta_proof::DeltaWitness, merkle_path::MerklePath, nullifier_key::NullifierKey,
    resource::Resource,
};
use rand::Rng;

// This function initializes a counter resource with a value of 1 and returns it
// along with a nullifier key.
pub fn init_counter_resource() -> (Resource, NullifierKey) {
    let mut rng = rand::thread_rng();
    let (nf_key, nf_key_cm) = NullifierKey::random_pair();
    let label_ref: [u8; 32] = rng.gen(); // Random label reference, it should be unique for each counter
    let counter_resource = Resource::create(
        counter_logic_ref(),
        label_ref.to_vec(),
        1,
        convert_counter_to_value_ref(1u128), // Initialize with value/counter 1
        false,
        nf_key_cm,
    );
    (counter_resource, nf_key)
}

// This function creates an ephemeral counter resource based on an initialized
// counter. It resets the nonce, sets the value to 0, and generates a new
// nullifier key.
pub fn ephemeral_counter(inited_counter: &Resource) -> (Resource, NullifierKey) {
    let (nf_key, nf_key_cm) = NullifierKey::random_pair();
    let mut ephemeral_counter = inited_counter.clone();
    ephemeral_counter.is_ephemeral = true;
    ephemeral_counter.reset_randomness_nonce();
    ephemeral_counter.set_value_ref(convert_counter_to_value_ref(0u128));
    ephemeral_counter.set_nf_commitment(nf_key_cm.clone());
    (ephemeral_counter, nf_key)
}

// This function creates an initial transaction that initializes a counter
// resource. It generates a compliance proof and logic proofs, and constructs
// the transaction. The transaction is then returned along with the counter
// resource and nullifier key.
pub fn create_init_counter_tx() -> (Transaction, Resource, NullifierKey) {
    let (counter_resource, nf_key) = init_counter_resource();
    let (ephemeral_counter, ephemeral_nf_key) = ephemeral_counter(&counter_resource);
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
    let mut tx = Transaction::new(vec![action], Delta::Witness(delta_witness));
    tx.generate_delta_proof();
    (tx, counter_resource, nf_key)
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
