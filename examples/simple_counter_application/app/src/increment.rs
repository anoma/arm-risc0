use crate::{convert_counter_to_value_ref, generate_compliance_proof, generate_logic_proofs};
use arm::{
    action::Action,
    transaction::{Delta, Transaction},
};
use arm::{
    delta_proof::DeltaWitness, merkle_path::MerklePath, nullifier_key::NullifierKey,
    resource::Resource,
};

// This function creates a counter resource based on the old counter resource.
// It increments the counter value by 1 and returns the new counter resource.
pub fn increment_counter(old_counter: &Resource, old_counter_nf_key: &NullifierKey) -> Resource {
    let mut new_counter = old_counter.clone();
    let current_value = u128::from_le_bytes(new_counter.value_ref[0..16].try_into().unwrap());
    new_counter.set_value_ref(convert_counter_to_value_ref(current_value + 1));
    new_counter.reset_randomness();
    new_counter.set_nonce_from_nf(old_counter, old_counter_nf_key);
    new_counter
}

pub fn create_increment_tx(
    counter_resource: Resource,
    nf_key: NullifierKey,
) -> (Transaction, Resource) {
    let new_counter = increment_counter(&counter_resource, &nf_key);
    let (compliance_unit, rcv) = generate_compliance_proof(
        counter_resource.clone(),
        nf_key.clone(),
        MerklePath::default(),
        new_counter.clone(),
    );
    let logic_verifier_inputs =
        generate_logic_proofs(counter_resource, nf_key, new_counter.clone());

    let action = Action::new(vec![compliance_unit], logic_verifier_inputs, vec![]);
    let delta_witness = DeltaWitness::from_bytes(&rcv);
    let mut tx = Transaction::create(vec![action], Delta::Witness(delta_witness));
    tx.generate_delta_proof();
    (tx, new_counter)
}

#[test]
fn test_create_increment_tx() {
    use crate::init::create_init_counter_tx;

    let (init_tx, counter_resource, nf_key) = create_init_counter_tx();
    assert!(init_tx.verify(), "Initial transaction verification failed");
    let (increment_tx, new_counter) = create_increment_tx(counter_resource, nf_key);
    assert!(
        increment_tx.verify(),
        "Increment transaction verification failed"
    );
    let expected_value_ref = convert_counter_to_value_ref(2u128);
    assert_eq!(
        new_counter.value_ref, expected_value_ref,
        "New counter resource value should be 2"
    );
}
