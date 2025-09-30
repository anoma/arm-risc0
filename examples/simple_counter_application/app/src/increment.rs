use crate::{convert_counter_to_value_ref, generate_compliance_proof, generate_logic_proofs};
use arm::{
    action::Action,
    delta_proof::DeltaWitness,
    encryption::AffinePoint,
    error::ArmError,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    transaction::{Delta, Transaction},
};

// This function creates a counter resource based on the old counter resource.
// It increments the counter value by 1 and returns the new counter resource.
pub fn increment_counter(
    old_counter: &Resource,
    old_counter_nf_key: &NullifierKey,
) -> Result<Resource, ArmError> {
    let mut new_counter = *old_counter;
    let current_value = u128::from_le_bytes(
        new_counter.value_ref.as_bytes()[0..16]
            .try_into()
            .map_err(|_| ArmError::InvalidResourceValueRef)?,
    );
    new_counter.set_value_ref(convert_counter_to_value_ref(current_value + 1));
    new_counter.reset_randomness();
    new_counter.set_nonce_from_nf(old_counter, old_counter_nf_key)?;
    Ok(new_counter)
}

pub fn create_increment_tx(
    counter_resource: Resource,
    consumed_merkle_path: MerklePath,
    nf_key: NullifierKey,
    consumed_discovery_pk: AffinePoint,
    created_discovery_pk: AffinePoint,
) -> Result<(Transaction, Resource), ArmError> {
    let new_counter = increment_counter(&counter_resource, &nf_key)?;
    let (compliance_unit, rcv) = generate_compliance_proof(
        counter_resource,
        nf_key.clone(),
        consumed_merkle_path,
        new_counter,
    )?;
    let logic_verifier_inputs = generate_logic_proofs(
        counter_resource,
        nf_key,
        consumed_discovery_pk,
        new_counter,
        created_discovery_pk,
    )?;

    let action = Action::new(vec![compliance_unit], logic_verifier_inputs)?;
    let delta_witness = DeltaWitness::from_bytes(&rcv)?;
    let tx = Transaction::create(vec![action], Delta::Witness(delta_witness));
    let balanced_tx = tx.generate_delta_proof().unwrap();
    Ok((balanced_tx, new_counter))
}

#[test]
fn test_create_increment_tx() {
    use crate::init::create_init_counter_tx;
    use arm::encryption::{random_keypair, Ciphertext};

    let (discovery_sk, discovery_pk) = random_keypair();
    let (init_tx, counter_resource, nf_key) = create_init_counter_tx(discovery_pk).unwrap();
    init_tx.verify().unwrap();

    let consumed_merkle_path = MerklePath::default();
    let (increment_tx, new_counter) = create_increment_tx(
        counter_resource,
        consumed_merkle_path,
        nf_key,
        discovery_pk,
        discovery_pk,
    )
    .unwrap();

    // check the discovery ciphertext
    let discovery_ciphertext = Ciphertext::from_words(
        &increment_tx.actions[0].logic_verifier_inputs[0]
            .app_data
            .discovery_payload[0]
            .blob,
    );
    discovery_ciphertext.decrypt(&discovery_sk).unwrap();

    increment_tx.verify().unwrap();

    let expected_value_ref = convert_counter_to_value_ref(2u128);
    assert_eq!(
        new_counter.value_ref, expected_value_ref,
        "New counter resource value should be 2"
    );
}
