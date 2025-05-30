use aarm::logic_proof::{LogicProver, PaddingResourceLogic};
use aarm_core::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSigningKey, AuthorizationVerifyingKey},
    constants::COMMITMENT_TREE_DEPTH,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
};
use kudo_core::utils::{compute_kudo_label, compute_kudo_value, generate_receive_signature};
use kudo_resource::{KudoResourceLogic, KudoResourceLogicWitness};
use kudo_tx::swap::SwapInstance;
use simple_denomination::{SimpleDenominationResourceLogic, SimpleDenominationWitness};
use simple_receive::{SimpleReceiveLogic, SimpleReceiveWitness};

pub fn build_swap_tx(
    consumed_issuer: &AuthorizationVerifyingKey,
    owner_sk: &AuthorizationSigningKey,
    consumed_kudo_resource: &Resource,
    nf_key: &NullifierKey,
    consumed_kudo_path: MerklePath<COMMITMENT_TREE_DEPTH>,
    created_issuer: &AuthorizationVerifyingKey,
    created_kudo_quantity: u128,
) -> SwapInstance<
    KudoResourceLogic,
    SimpleDenominationResourceLogic,
    KudoResourceLogic,
    SimpleDenominationResourceLogic,
    SimpleReceiveLogic,
> {
    let (instant_nk, instant_nk_commitment) = NullifierKey::random_pair();

    // Construct the consumed kudo resource
    let kudo_logic = KudoResourceLogic::verifying_key();
    let consumed_kudo_lable = compute_kudo_label(&kudo_logic, consumed_issuer);
    assert_eq!(consumed_kudo_resource.label_ref, consumed_kudo_lable);
    let owner = AuthorizationVerifyingKey::from_signing_key(owner_sk);
    let kudo_value = compute_kudo_value(&owner);
    assert_eq!(kudo_value, consumed_kudo_resource.value_ref);
    let consumed_kudo_nf = consumed_kudo_resource.nullifier(nf_key).unwrap();

    // Construct the denomination resource corresponding to the consumed kudo resource
    let denomination_logic = SimpleDenominationResourceLogic::verifying_key();
    let consumed_denomination_resource = Resource::create(
        denomination_logic,
        [0u8; 32].into(), // TODO: fix the label?
        0,
        [0u8; 32].into(),
        true,
        instant_nk_commitment,
    );
    let consumed_denomination_resource_cm = consumed_denomination_resource.commitment();

    // Construct the created kudo resource: same ownership(kudo_value and
    // nk_commitment) as the consumed kudo resource
    let created_kudo_lable = compute_kudo_label(&kudo_logic, created_issuer);
    let created_kudo_resource = Resource::create(
        kudo_logic,
        created_kudo_lable,
        created_kudo_quantity,
        kudo_value, // use the same kudo value as the consumed kudo resource
        false,
        consumed_kudo_resource.nk_commitment, // use the same nk_commitment as the consumed kudo resource
    );
    let created_kudo_value_cm = created_kudo_resource.commitment();

    // Construct the denomination resource corresponding to the created kudo resource
    let created_denomination_resource = Resource::create(
        denomination_logic,
        [0u8; 32].into(), // TODO: fix the label?
        0,
        [0u8; 32].into(),
        true,
        instant_nk_commitment,
    );
    let created_denomination_resource_nf = created_denomination_resource
        .nullifier(&instant_nk)
        .unwrap();

    // Construct the receive logic resource
    let receive_resource = Resource::create(
        SimpleReceiveLogic::verifying_key(),
        created_kudo_value_cm,
        0,
        [0u8; 32].into(),
        true,
        instant_nk_commitment,
    );
    let receive_resource_cm = receive_resource.commitment();

    // Construct the padding resource
    let padding_resource = PaddingResourceLogic::create_padding_resource(instant_nk_commitment);
    let padding_resource_nf = padding_resource.nullifier(&instant_nk).unwrap();

    // Construct the action tree
    let action_tree = MerkleTree::new(vec![
        consumed_kudo_nf,
        consumed_denomination_resource_cm,
        created_denomination_resource_nf,
        created_kudo_value_cm,
        padding_resource_nf,
        receive_resource_cm,
    ]);
    let root = action_tree.root();

    // Generate paths
    let consumed_kudo_existence_path = action_tree.generate_path(consumed_kudo_nf).unwrap();
    let consumed_denomination_existence_path = action_tree
        .generate_path(consumed_denomination_resource_cm)
        .unwrap();
    let created_denomination_existence_path = action_tree
        .generate_path(created_denomination_resource_nf)
        .unwrap();
    let created_kudo_existence_path = action_tree.generate_path(created_kudo_value_cm).unwrap();
    let padding_resource_existence_path = action_tree.generate_path(padding_resource_nf).unwrap();
    let receive_existence_path = action_tree.generate_path(receive_resource_cm).unwrap();

    // Construct the consumed kudo witness
    let consumed_kudo = KudoResourceLogicWitness::generate_persistent_resource_consumption_witness(
        *consumed_kudo_resource,
        consumed_kudo_existence_path,
        *nf_key,
        *consumed_issuer,
        consumed_denomination_resource,
        consumed_denomination_existence_path,
        false,
    )
    .into();

    // Construct the denomination witness corresponding to the consumed kudo resource
    let consumption_signature = owner_sk.sign(root.as_bytes());
    let consumed_denomination =
        SimpleDenominationWitness::generate_persistent_resource_consumption_witness(
            consumed_denomination_resource,
            consumed_denomination_existence_path,
            consumption_signature,
            *consumed_kudo_resource,
            consumed_kudo_existence_path,
            *nf_key,
            *consumed_issuer,
            owner,
        )
        .into();

    // Construct the created kudo witness
    let receiver_signature =
        generate_receive_signature(&SimpleReceiveLogic::verifying_key(), owner_sk);
    let created_kudo = KudoResourceLogicWitness::generate_persistent_resource_creation_witness(
        created_kudo_resource,
        created_kudo_existence_path,
        *created_issuer,
        created_denomination_resource,
        created_denomination_existence_path,
        instant_nk,
        true,
        receive_resource,
        instant_nk,
        false,
        receive_existence_path,
        owner,
        receiver_signature,
    )
    .into();

    // Construct the denomination witness corresponding to the created kudo resource
    let created_denomination =
        SimpleDenominationWitness::generate_persistent_resource_creation_witness(
            created_denomination_resource,
            created_denomination_existence_path,
            true,
            instant_nk,
            created_kudo_resource,
            created_kudo_existence_path,
            *created_issuer,
        )
        .into();

    // Construct the receive witness
    let created_receive = SimpleReceiveWitness::generate_witness(
        receive_resource,
        receive_existence_path,
        instant_nk,
        false,
        created_kudo_resource,
        created_kudo_existence_path,
    )
    .into();

    // Construct the padding logic witness
    let padding_resource_logic = PaddingResourceLogic::new(
        padding_resource,
        padding_resource_existence_path,
        instant_nk,
        true,
    );

    SwapInstance {
        consumed_kudo,
        consumed_denomination,
        created_kudo,
        created_denomination,
        padding_resource_logic,
        created_receive,
        consumed_kudo_path,
    }
}

#[test]
fn generate_a_swap_tx() {
    use aarm::transaction::Transaction;

    let kudo_logic = KudoResourceLogic::verifying_key();
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

    let alice_consumed_kudo_resource = Resource::create(
        kudo_logic,
        alice_consumed_kudo_lable,
        alice_consumed_kudo_quantity,
        alice_kudo_value,
        false,
        alice_kudo_nk_cm,
    );

    let alice_created_issuer_sk = AuthorizationSigningKey::new();
    let alice_created_issuer =
        AuthorizationVerifyingKey::from_signing_key(&alice_created_issuer_sk);
    let alice_created_kudo_lable = compute_kudo_label(&kudo_logic, &alice_created_issuer);
    let alice_created_kudo_quantity = 200;

    let alice_swap_witness = build_swap_tx(
        &alice_consumed_issuer,
        &alice_sk,
        &alice_consumed_kudo_resource,
        &alice_kudo_nf_key,
        MerklePath::<COMMITMENT_TREE_DEPTH>::default(), // It should be a real path
        &alice_created_issuer,
        alice_created_kudo_quantity,
    );

    let alice_tx = alice_swap_witness.create_tx();

    let bob_sk = AuthorizationSigningKey::new();
    let bob_pk = AuthorizationVerifyingKey::from_signing_key(&bob_sk);
    let bob_kudo_value = compute_kudo_value(&bob_pk);
    let (bob_kudo_nf_key, bob_kudo_nk_cm) = NullifierKey::random_pair();
    let bob_consumed_kudo_resource = Resource::create(
        kudo_logic,
        alice_created_kudo_lable,
        alice_created_kudo_quantity,
        bob_kudo_value,
        false,
        bob_kudo_nk_cm,
    );
    let bob_consumed_issuer = alice_created_issuer;
    let bob_created_issuer = alice_consumed_issuer;
    let bob_created_kudo_quantity = alice_consumed_kudo_quantity;
    let bob_swap_witness = build_swap_tx(
        &bob_consumed_issuer,
        &bob_sk,
        &bob_consumed_kudo_resource,
        &bob_kudo_nf_key,
        MerklePath::<COMMITMENT_TREE_DEPTH>::default(), // It should be a real path
        &bob_created_issuer,
        bob_created_kudo_quantity,
    );
    let bob_tx = bob_swap_witness.create_tx();

    let mut tx = Transaction::compose(alice_tx, bob_tx);
    tx.generate_delta_proof();
    assert!(tx.verify());
}
