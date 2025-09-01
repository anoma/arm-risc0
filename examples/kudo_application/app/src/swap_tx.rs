use crate::{
    kudo_main::KudoMainInfo, simple_denomination::SimpleDenominationInfo,
    simple_receive::SimpleReceiveInfo,
};
use arm::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSigningKey, AuthorizationVerifyingKey},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    utils::words_to_bytes,
};
use arm::{
    logic_proof::{LogicProver, PaddingResourceLogic},
    transaction::Transaction,
};
use kudo_logic_witness::{
    kudo_main_witness::KudoMainWitness,
    simple_denomination_witness::SimpleDenominationLogicWitness,
    simple_receive_witness::SimpleReceiveLogicWitness,
    utils::{compute_kudo_label, compute_kudo_value, generate_receive_signature},
};
use kudo_traits::swap::Swap;
use rand::Rng;

pub fn build_swap_tx(
    consumed_issuer: &AuthorizationVerifyingKey,
    owner_sk: &AuthorizationSigningKey,
    consumed_kudo_resource: &Resource,
    nf_key: &NullifierKey,
    consumed_kudo_path: MerklePath,
    created_issuer: &AuthorizationVerifyingKey,
    created_kudo_quantity: u128,
) -> Transaction {
    let (instant_nk, instant_nk_commitment) = NullifierKey::random_pair();

    // Construct the consumed kudo resource
    let kudo_logic = KudoMainInfo::verifying_key_as_bytes();
    let consumed_kudo_lable = compute_kudo_label(&kudo_logic, consumed_issuer);
    assert_eq!(consumed_kudo_resource.label_ref, consumed_kudo_lable);
    let owner = AuthorizationVerifyingKey::from_signing_key(owner_sk);
    let kudo_value = compute_kudo_value(&owner);
    assert_eq!(kudo_value, consumed_kudo_resource.value_ref);
    let consumed_kudo_nf = consumed_kudo_resource.nullifier(nf_key).unwrap();

    // Construct the created kudo resource: same ownership(kudo_value and
    // nk_commitment) as the consumed kudo resource
    let created_kudo_lable = compute_kudo_label(&kudo_logic, created_issuer);
    let created_kudo_resource = Resource::create(
        kudo_logic.clone(),
        created_kudo_lable,
        created_kudo_quantity,
        kudo_value, // use the same kudo value as the consumed kudo resource
        false,
        consumed_kudo_nf.as_bytes().to_vec(),
        consumed_kudo_resource.nk_commitment.clone(), // use the same nk_commitment as the consumed kudo resource
    );
    let created_kudo_value_cm = created_kudo_resource.commitment();

    // Construct the denomination resource corresponding to the consumed kudo resource
    let denomination_logic = SimpleDenominationInfo::verifying_key_as_bytes();
    let mut rng = rand::thread_rng();
    let nonce: [u8; 32] = rng.gen(); // Random nonce for the ephemeral resource
    let consumed_denomination_resource = Resource::create(
        denomination_logic.clone(),
        consumed_kudo_nf.as_bytes().to_vec(), // Use the consumed kudo nullifier as the label
        0,
        [0u8; 32].into(),
        true,
        nonce.to_vec(),
        instant_nk_commitment.clone(),
    );
    let consumed_denomination_resource_nf = consumed_denomination_resource
        .nullifier(&instant_nk)
        .unwrap();

    // Construct the denomination resource corresponding to the created kudo resource
    let created_denomination_resource = Resource::create(
        denomination_logic.clone(),
        created_kudo_value_cm.as_bytes().to_vec(), // Use the created kudo commitment as the label
        0,
        [0u8; 32].into(),
        true,
        consumed_denomination_resource_nf.as_bytes().to_vec(),
        instant_nk_commitment.clone(),
    );
    let created_denomination_resource_cm = created_denomination_resource.commitment();

    // Construct the padding resource
    let padding_resource =
        PaddingResourceLogic::create_padding_resource(instant_nk_commitment.clone());
    let padding_resource_nf = padding_resource.nullifier(&instant_nk).unwrap();

    // Construct the receive logic resource
    let receive_resource = Resource::create(
        SimpleReceiveInfo::verifying_key_as_bytes(),
        created_kudo_value_cm.as_bytes().to_vec(),
        0,
        [0u8; 32].into(),
        true,
        padding_resource_nf.as_bytes().to_vec(),
        instant_nk_commitment.clone(),
    );
    let receive_resource_cm = receive_resource.commitment();

    // Construct the action tree
    let action_tree = MerkleTree::new(vec![
        consumed_kudo_nf,
        created_kudo_value_cm,
        consumed_denomination_resource_nf,
        created_denomination_resource_cm,
        padding_resource_nf,
        receive_resource_cm,
    ]);
    let root = action_tree.root();
    let root_bytes = words_to_bytes(&root);

    // Generate paths
    let consumed_kudo_existence_path = action_tree.generate_path(&consumed_kudo_nf).unwrap();
    let consumed_denomination_existence_path = action_tree
        .generate_path(&consumed_denomination_resource_nf)
        .unwrap();
    let created_denomination_existence_path = action_tree
        .generate_path(&created_denomination_resource_cm)
        .unwrap();
    let created_kudo_existence_path = action_tree.generate_path(&created_kudo_value_cm).unwrap();
    let padding_resource_existence_path = action_tree.generate_path(&padding_resource_nf).unwrap();
    let receive_existence_path = action_tree.generate_path(&receive_resource_cm).unwrap();

    // Construct the consumed kudo witness
    let consumed_kudo_logic_witness =
        KudoMainWitness::generate_persistent_resource_consumption_witness(
            consumed_kudo_resource.clone(),
            consumed_kudo_existence_path.clone(),
            nf_key.clone(),
            *consumed_issuer,
            consumed_denomination_resource.clone(),
            consumed_denomination_existence_path.clone(),
            true,
            instant_nk.clone(),
        );
    let consumed_kudo = KudoMainInfo::new(consumed_kudo_logic_witness, Some(consumed_kudo_path));

    // Construct the denomination witness corresponding to the consumed kudo resource
    let consumption_signature = owner_sk.sign(root_bytes);
    let consumed_denomination_logic_witness =
        SimpleDenominationLogicWitness::generate_denomimation_witness(
            consumed_denomination_resource.clone(),
            consumed_denomination_existence_path.clone(),
            true,
            instant_nk.clone(),
            consumption_signature,
            consumed_kudo_resource.clone(),
            consumed_kudo_existence_path.clone(),
            true, // The kudo resource is consumed
            nf_key.clone(),
            *consumed_issuer,
            owner,
        );
    let consumed_denomination =
        SimpleDenominationInfo::new(consumed_denomination_logic_witness, None);

    // Construct the created kudo witness
    let receiver_signature =
        generate_receive_signature(&SimpleReceiveInfo::verifying_key_as_bytes(), owner_sk);
    let created_kudo_logic_witness = KudoMainWitness::generate_persistent_resource_creation_witness(
        created_kudo_resource.clone(),
        created_kudo_existence_path.clone(),
        *created_issuer,
        created_denomination_resource.clone(),
        created_denomination_existence_path.clone(),
        NullifierKey::default(), // Not used in this case
        false,
        receive_resource.clone(),
        NullifierKey::default(), // Not used in this case
        false,
        receive_existence_path.clone(),
        owner,
        receiver_signature,
    );
    let created_kudo = KudoMainInfo::new(created_kudo_logic_witness, None);

    // Construct the denomination witness corresponding to the created kudo resource
    let created_denomination_logic_witness =
        SimpleDenominationLogicWitness::generate_created_kudo_denomination_witness(
            created_denomination_resource.clone(),
            created_denomination_existence_path.clone(),
            false,
            NullifierKey::default(), // Not used in this case
            created_kudo_resource.clone(),
            created_kudo_existence_path.clone(),
            *created_issuer,
        );
    let created_denomination =
        SimpleDenominationInfo::new(created_denomination_logic_witness, None);

    // Construct the receive witness
    let created_receive_logic_witness = SimpleReceiveLogicWitness::generate_witness(
        receive_resource.clone(),
        receive_existence_path.clone(),
        instant_nk.clone(),
        false,
        created_kudo_resource.clone(),
        created_kudo_existence_path.clone(),
    );
    let created_receive = SimpleReceiveInfo::new(created_receive_logic_witness, None);

    // Construct the padding logic witness
    let padding_resource_logic = PaddingResourceLogic::new(
        padding_resource,
        padding_resource_existence_path,
        instant_nk,
        true,
    );

    let swap = Swap {
        consumed_kudo,
        consumed_denomination,
        created_kudo,
        created_denomination,
        padding_resource_logic,
        created_receive,
    };

    swap.create_tx()
}

#[test]
fn generate_a_swap_tx() {
    use arm::transaction::Transaction;
    use std::time::Instant;

    let kudo_logic = KudoMainInfo::verifying_key_as_bytes();
    // The issuer determines the kind of kudo
    let alice_consumed_issuer_sk = AuthorizationSigningKey::new();
    let alice_consumed_issuer =
        AuthorizationVerifyingKey::from_signing_key(&alice_consumed_issuer_sk);
    let alice_consumed_kudo_lable = compute_kudo_label(&kudo_logic, &alice_consumed_issuer);

    // The consumed and created kudo resources share the same ownership(value and nk)
    let alice_sk = AuthorizationSigningKey::new();
    let alice_pk = AuthorizationVerifyingKey::from_signing_key(&alice_sk);
    let alice_kudo_value = compute_kudo_value(&alice_pk);
    let (alice_kudo_nf_key, alice_kudo_nk_cm) = NullifierKey::random_pair();
    let alice_consumed_kudo_quantity = 100;
    let nonce = vec![0u8; 32]; // Use a fixed nonce for testing

    let alice_consumed_kudo_resource = Resource::create(
        kudo_logic.clone(),
        alice_consumed_kudo_lable,
        alice_consumed_kudo_quantity,
        alice_kudo_value,
        false,
        nonce,
        alice_kudo_nk_cm,
    );

    let alice_created_issuer_sk = AuthorizationSigningKey::new();
    let alice_created_issuer =
        AuthorizationVerifyingKey::from_signing_key(&alice_created_issuer_sk);
    let alice_created_kudo_lable = compute_kudo_label(&kudo_logic, &alice_created_issuer);
    let alice_created_kudo_quantity = 200;

    let alice_tx = build_swap_tx(
        &alice_consumed_issuer,
        &alice_sk,
        &alice_consumed_kudo_resource,
        &alice_kudo_nf_key,
        MerklePath::default(), // It should be a real path
        &alice_created_issuer,
        alice_created_kudo_quantity,
    );

    let bob_sk = AuthorizationSigningKey::new();
    let bob_pk = AuthorizationVerifyingKey::from_signing_key(&bob_sk);
    let bob_kudo_value = compute_kudo_value(&bob_pk);
    let (bob_kudo_nf_key, bob_kudo_nk_cm) = NullifierKey::random_pair();
    let nonce = vec![1u8; 32]; // Use a fixed nonce for testing
    let bob_consumed_kudo_resource = Resource::create(
        kudo_logic,
        alice_created_kudo_lable,
        alice_created_kudo_quantity,
        bob_kudo_value,
        false,
        nonce,
        bob_kudo_nk_cm,
    );
    let bob_consumed_issuer = alice_created_issuer;
    let bob_created_issuer = alice_consumed_issuer;
    let bob_created_kudo_quantity = alice_consumed_kudo_quantity;

    let tx_start_timer = Instant::now();
    let bob_tx = build_swap_tx(
        &bob_consumed_issuer,
        &bob_sk,
        &bob_consumed_kudo_resource,
        &bob_kudo_nf_key,
        MerklePath::default(), // It should be a real path
        &bob_created_issuer,
        bob_created_kudo_quantity,
    );

    let mut tx = Transaction::compose(alice_tx, bob_tx);
    tx.generate_delta_proof();
    println!("Tx build duration time: {:?}", tx_start_timer.elapsed());

    let tx_verify_start_timer = Instant::now();
    assert!(tx.verify());
    println!(
        "TX verify duration time: {:?}",
        tx_verify_start_timer.elapsed()
    );
}
