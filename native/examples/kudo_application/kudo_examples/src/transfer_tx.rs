use aarm::logic_proof::{LogicProver, PaddingResourceLogic};
use aarm_core::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSignature, AuthorizationSigningKey, AuthorizationVerifyingKey},
    constants::COMMITMENT_TREE_DEPTH,
    merkle_path::MerklePath,
    nullifier_key::{NullifierKey, NullifierKeyCommitment},
    resource::Resource,
};
use kudo_core::utils::{compute_kudo_label, compute_kudo_value};
use kudo_resource::{KudoResourceLogic, KudoResourceLogicWitness};
use kudo_tx::transfer::TransferInstance;
use simple_denomination::{SimpleDenominationResourceLogic, SimpleDenominationWitness};
use simple_receive::{SimpleReceiveLogic, SimpleReceiveWitness};

pub fn build_transfer_tx(
    issuer: &AuthorizationVerifyingKey,
    owner_sk: &AuthorizationSigningKey,
    consumed_kudo_resource: &Resource,
    consumed_kudo_nf_key: &NullifierKey,
    consumed_kudo_path: MerklePath<COMMITMENT_TREE_DEPTH>,
    receiver_pk: &AuthorizationVerifyingKey,
    receiver_signature: &AuthorizationSignature,
    receiver_nk_commitment: &NullifierKeyCommitment,
) -> TransferInstance<KudoResourceLogic, SimpleDenominationResourceLogic, SimpleReceiveLogic> {
    let (instant_nk, instant_nk_commitment) = NullifierKey::random_pair();

    // Construct the consumed kudo resource
    let kudo_logic = KudoResourceLogic::verifying_key();
    let kudo_lable = compute_kudo_label(&kudo_logic, issuer);
    assert_eq!(consumed_kudo_resource.label_ref, kudo_lable);
    let owner = AuthorizationVerifyingKey::from_signing_key(owner_sk);
    let kudo_value = compute_kudo_value(&owner);
    assert_eq!(kudo_value, consumed_kudo_resource.value_ref);
    let consumed_kudo_nf = consumed_kudo_resource
        .nullifier(consumed_kudo_nf_key)
        .unwrap();

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

    // Construct the created kudo resource
    let mut created_kudo_resource = consumed_kudo_resource.clone();
    // Set the new ownership to the created kudo resource
    created_kudo_resource.set_nf_commitment(*receiver_nk_commitment);
    let created_kudo_value = compute_kudo_value(receiver_pk);
    created_kudo_resource.set_value_ref(created_kudo_value);
    // Reset the randomness and nonce
    created_kudo_resource.reset_randomness_nonce();
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
        *consumed_kudo_nf_key,
        *issuer,
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
            *consumed_kudo_nf_key,
            *issuer,
            owner,
        )
        .into();

    // Construct the created kudo witness
    let created_kudo = KudoResourceLogicWitness::generate_persistent_resource_creation_witness(
        created_kudo_resource.clone(),
        created_kudo_existence_path,
        *issuer,
        created_denomination_resource,
        created_denomination_existence_path,
        instant_nk,
        true,
        receive_resource,
        instant_nk,
        false,
        receive_existence_path,
        *receiver_pk,
        *receiver_signature,
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
            *issuer,
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

    TransferInstance {
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
fn generate_a_transfer_tx() {
    use kudo_core::utils::generate_receive_signature;

    let kudo_logic = KudoResourceLogic::verifying_key();
    let issuer_sk = AuthorizationSigningKey::new();
    let issuer = AuthorizationVerifyingKey::from_signing_key(&issuer_sk);
    let kudo_lable = compute_kudo_label(&kudo_logic, &issuer);
    let owner_sk = AuthorizationSigningKey::new();
    let owner = AuthorizationVerifyingKey::from_signing_key(&owner_sk);
    let kudo_value = compute_kudo_value(&owner);
    let (kudo_nf_key, kudo_nk_cm) = NullifierKey::random_pair();

    let (receiver_pk, receiver_signature) = {
        let sk = AuthorizationSigningKey::new();
        let pk = AuthorizationVerifyingKey::from_signing_key(&sk);
        let signature = generate_receive_signature(&SimpleReceiveLogic::verifying_key(), &sk);
        (pk, signature)
    };
    let (_receiver_nf_key, receiver_nk_commitment) = NullifierKey::random_pair();

    let consumed_kudo_resource =
        Resource::create(kudo_logic, kudo_lable, 100, kudo_value, false, kudo_nk_cm);

    let transfer_witness = build_transfer_tx(
        &issuer,
        &owner_sk,
        &consumed_kudo_resource,
        &kudo_nf_key,
        MerklePath::<COMMITMENT_TREE_DEPTH>::default(), // It should be a real path
        &receiver_pk,
        &receiver_signature,
        &receiver_nk_commitment,
    );

    let mut tx = transfer_witness.create_tx();
    tx.generate_delta_proof();

    assert!(tx.verify());
}
