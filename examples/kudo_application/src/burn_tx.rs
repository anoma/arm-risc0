use aarm::logic_proof::LogicProver;
use aarm_core::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSigningKey, AuthorizationVerifyingKey},
    constants::COMMITMENT_TREE_DEPTH,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
};
use kudo_core::utils::{compute_kudo_label, compute_kudo_value};
use kudo_resource::{KudoResourceLogic, KudoResourceLogicWitness};
use kudo_tx::burn::BurnInstance;
use simple_denomination::{SimpleDenominationResourceLogic, SimpleDenominationWitness};

pub fn build_burn_tx(
    issuer_sk: &AuthorizationSigningKey,
    owner_sk: &AuthorizationSigningKey,
    burned_kudo_resource: &Resource,
    burned_kudoresource_nf_key: &NullifierKey,
    burned_kudo_path: MerklePath<COMMITMENT_TREE_DEPTH>,
) -> BurnInstance<KudoResourceLogic, SimpleDenominationResourceLogic> {
    let issuer = AuthorizationVerifyingKey::from_signing_key(issuer_sk);
    let (instant_nk, instant_nk_commitment) = NullifierKey::random_pair();

    // Construct the burned kudo resource
    let kudo_lable = compute_kudo_label(&KudoResourceLogic::verifying_key(), &issuer);
    assert_eq!(burned_kudo_resource.label_ref, kudo_lable);
    let owner = AuthorizationVerifyingKey::from_signing_key(owner_sk);
    let kudo_value = compute_kudo_value(&owner);
    assert_eq!(kudo_value, burned_kudo_resource.value_ref);
    let burned_kudo_resource_nf = burned_kudo_resource
        .nullifier(burned_kudoresource_nf_key)
        .unwrap();

    // Construct the burned denomination resource
    let denomination_logic = SimpleDenominationResourceLogic::verifying_key();
    let burned_denomination_resource = Resource::create(
        denomination_logic,
        [0u8; 32].into(), // TODO: fix the label?
        0,
        [0u8; 32].into(),
        true,
        instant_nk_commitment,
    );
    let burned_denomination_resource_cm = burned_denomination_resource.commitment();

    // Construct the ephemeral kudo resource
    let mut ephemeral_kudo_resource = *burned_kudo_resource;
    ephemeral_kudo_resource.is_ephemeral = true;
    let ephemeral_kudo_resource_cm = ephemeral_kudo_resource.commitment();

    // Construct the ephemeral denomination resource
    let ephemeral_denomination_resource = Resource::create(
        denomination_logic,
        [0u8; 32].into(), // TODO: fix the label?
        0,
        [0u8; 32].into(),
        true,
        instant_nk_commitment,
    );
    let ephemeral_denomination_resource_nf = ephemeral_denomination_resource
        .nullifier(&instant_nk)
        .unwrap();

    // Construct the action tree
    let action_tree = MerkleTree::new(vec![
        burned_kudo_resource_nf,
        burned_denomination_resource_cm,
        ephemeral_denomination_resource_nf,
        ephemeral_kudo_resource_cm,
    ]);
    let root = action_tree.root();

    // Generate paths
    let burned_kudo_existence_path = action_tree.generate_path(burned_kudo_resource_nf).unwrap();
    let burned_denomination_existence_path = action_tree
        .generate_path(burned_denomination_resource_cm)
        .unwrap();
    let ephemeral_denomination_existence_path = action_tree
        .generate_path(ephemeral_denomination_resource_nf)
        .unwrap();
    let ephemeral_kudo_existence_path = action_tree
        .generate_path(ephemeral_kudo_resource_cm)
        .unwrap();

    // Construct the burned kudo witness: consume the kudo resource
    let burned_kudo = KudoResourceLogicWitness::generate_persistent_resource_consumption_witness(
        *burned_kudo_resource,
        burned_kudo_existence_path,
        *burned_kudoresource_nf_key,
        issuer,
        burned_denomination_resource,
        burned_denomination_existence_path,
        false,
    )
    .into();

    // Construct the denomination witness corresponding to the consumed kudo resource
    let consumption_signature = owner_sk.sign(root.as_bytes());
    let burned_denomination =
        SimpleDenominationWitness::generate_persistent_resource_consumption_witness(
            burned_denomination_resource,
            burned_denomination_existence_path,
            consumption_signature,
            *burned_kudo_resource,
            burned_kudo_existence_path,
            *burned_kudoresource_nf_key,
            issuer,
            owner,
        )
        .into();

    // Construct the ephemeral kudo witness
    let ephemeral_kudo = KudoResourceLogicWitness::generate_created_ephemeral_witness(
        ephemeral_kudo_resource,
        ephemeral_kudo_existence_path,
        issuer,
        ephemeral_denomination_resource,
        ephemeral_denomination_existence_path,
        instant_nk,
    )
    .into();

    // Construct the denomination witness, corresponding to the ephemeral kudo resource
    let burn_signature = issuer_sk.sign(root.as_bytes());
    let ephemeral_denomination = SimpleDenominationWitness::generate_burned_ephemeral_witness(
        ephemeral_denomination_resource,
        ephemeral_denomination_existence_path,
        instant_nk,
        burn_signature,
        ephemeral_kudo_resource,
        ephemeral_kudo_existence_path,
        issuer,
        owner,
    )
    .into();

    BurnInstance {
        burned_kudo,
        burned_denomination,
        ephemeral_kudo,
        ephemeral_denomination,
        burned_kudo_path,
    }
}

#[test]
fn generate_a_burn_tx() {
    let issuer_sk = AuthorizationSigningKey::new();
    let issuer = AuthorizationVerifyingKey::from_signing_key(&issuer_sk);
    // TODO: fix the kudo_logic
    let kudo_logic = KudoResourceLogic::verifying_key();
    let kudo_lable = compute_kudo_label(&kudo_logic, &issuer);
    let owner_sk = issuer_sk.clone();
    let owner = AuthorizationVerifyingKey::from_signing_key(&owner_sk);
    let kudo_value = compute_kudo_value(&owner);
    let (kudo_nf_key, kudo_nk_cm) = NullifierKey::random_pair();

    let kudo_resource =
        Resource::create(kudo_logic, kudo_lable, 100, kudo_value, false, kudo_nk_cm);

    let burn_witness = build_burn_tx(
        &issuer_sk,
        &owner_sk,
        &kudo_resource,
        &kudo_nf_key,
        MerklePath::<COMMITMENT_TREE_DEPTH>::default(), // It should be a real path
    );

    let mut tx = burn_witness.create_tx();
    tx.generate_delta_proof();

    assert!(tx.verify());
}
