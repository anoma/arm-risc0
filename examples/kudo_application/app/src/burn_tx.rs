use crate::{kudo_main::KudoMainInfo, simple_denomination::SimpleDenominationInfo};
use arm::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSigningKey, AuthorizationVerifyingKey},
    merkle_path::MerklePath,
    merkle_path::COMMITMENT_TREE_DEPTH,
    nullifier_key::NullifierKey,
    resource::Resource,
};
use arm::{logic_proof::LogicProver, transaction::Transaction};
use kudo_logic_witness::{
    kudo_main_witness::KudoMainWitness,
    simple_denomination_witness::SimpleDenominationLogicWitness,
    utils::{compute_kudo_label, compute_kudo_value},
};
use kudo_traits::burn::Burn;
use rand::Rng;

pub fn build_burn_tx(
    issuer_sk: &AuthorizationSigningKey,
    owner_sk: &AuthorizationSigningKey,
    burned_kudo_resource: &Resource,
    burned_kudoresource_nf_key: &NullifierKey,
    burned_kudo_path: MerklePath<COMMITMENT_TREE_DEPTH>,
) -> Transaction {
    let issuer = AuthorizationVerifyingKey::from_signing_key(issuer_sk);
    let (instant_nk, instant_nk_commitment) = NullifierKey::random_pair();

    // Construct the burned kudo resource
    let kudo_lable = compute_kudo_label(&KudoMainInfo::verifying_key_as_bytes(), &issuer);
    assert_eq!(burned_kudo_resource.label_ref, kudo_lable);
    let owner = AuthorizationVerifyingKey::from_signing_key(owner_sk);
    let kudo_value = compute_kudo_value(&owner);
    assert_eq!(kudo_value, burned_kudo_resource.value_ref);
    let burned_kudo_resource_nf = burned_kudo_resource
        .nullifier(burned_kudoresource_nf_key)
        .unwrap();

    // Construct the ephemeral kudo resource
    let mut ephemeral_kudo_resource = burned_kudo_resource.clone();
    ephemeral_kudo_resource.is_ephemeral = true;
    ephemeral_kudo_resource.reset_randomness();
    ephemeral_kudo_resource.set_nonce(burned_kudo_resource_nf.as_bytes().to_vec());
    let ephemeral_kudo_resource_cm = ephemeral_kudo_resource.commitment();

    // Construct the ephemeral denomination resource
    let denomination_logic = SimpleDenominationInfo::verifying_key_as_bytes();
    let mut rng = rand::thread_rng();
    let nonce: [u8; 32] = rng.gen(); // Random nonce for the ephemeral resource
    let ephemeral_denomination_resource = Resource::create(
        denomination_logic.clone(),
        ephemeral_kudo_resource_cm.as_bytes().to_vec(), // Use the ephemeral kudo commitment as the label
        0,
        [0u8; 32].into(),
        true,
        nonce.to_vec(),
        instant_nk_commitment.clone(),
    );
    let ephemeral_denomination_resource_nf = ephemeral_denomination_resource
        .nullifier(&instant_nk)
        .unwrap();

    // Construct the burned denomination resource
    let burned_denomination_resource = Resource::create(
        denomination_logic.clone(),
        burned_kudo_resource_nf.as_bytes().to_vec(), // Use the burned kudo nullifier as the label
        0,
        [0u8; 32].into(),
        true,
        ephemeral_denomination_resource_nf.as_bytes().to_vec(),
        instant_nk_commitment.clone(),
    );
    let burned_denomination_resource_cm = burned_denomination_resource.commitment();

    // Construct the action tree
    let action_tree = MerkleTree::new(vec![
        burned_kudo_resource_nf,
        ephemeral_kudo_resource_cm,
        ephemeral_denomination_resource_nf,
        burned_denomination_resource_cm,
    ]);
    let root = action_tree.root();

    // Generate paths
    let burned_kudo_existence_path = action_tree.generate_path(&burned_kudo_resource_nf).unwrap();
    let burned_denomination_existence_path = action_tree
        .generate_path(&burned_denomination_resource_cm)
        .unwrap();
    let ephemeral_denomination_existence_path = action_tree
        .generate_path(&ephemeral_denomination_resource_nf)
        .unwrap();
    let ephemeral_kudo_existence_path = action_tree
        .generate_path(&ephemeral_kudo_resource_cm)
        .unwrap();

    // Construct the burned kudo witness: consume the kudo resource
    let burned_kudo_logic_witness =
        KudoMainWitness::generate_persistent_resource_consumption_witness(
            burned_kudo_resource.clone(),
            burned_kudo_existence_path.clone(),
            burned_kudoresource_nf_key.clone(),
            issuer,
            burned_denomination_resource.clone(),
            burned_denomination_existence_path.clone(),
            false,
            NullifierKey::default(), // Not used in this case
        );
    let burned_kudo_info = KudoMainInfo::new(burned_kudo_logic_witness, Some(burned_kudo_path));

    // Construct the denomination witness corresponding to the consumed kudo resource
    let consumption_signature = owner_sk.sign(root.as_bytes());
    let burned_denomination_logic_witness =
        SimpleDenominationLogicWitness::generate_denomimation_witness(
            burned_denomination_resource,
            burned_denomination_existence_path,
            false,
            NullifierKey::default(), // Not used in this case
            consumption_signature,
            burned_kudo_resource.clone(),
            burned_kudo_existence_path,
            true, // The kudo resource is consumed
            burned_kudoresource_nf_key.clone(),
            issuer,
            owner,
        );
    let burned_denomination_info =
        SimpleDenominationInfo::new(burned_denomination_logic_witness, None);

    // Construct the ephemeral kudo witness
    let ephemeral_kudo_logic_witness = KudoMainWitness::generate_created_ephemeral_witness(
        ephemeral_kudo_resource.clone(),
        ephemeral_kudo_existence_path.clone(),
        issuer,
        ephemeral_denomination_resource.clone(),
        ephemeral_denomination_existence_path.clone(),
        instant_nk.clone(),
    );
    let ephemeral_kudo_info = KudoMainInfo::new(ephemeral_kudo_logic_witness, None);

    // Construct the denomination witness, corresponding to the ephemeral kudo resource
    let burn_signature = issuer_sk.sign(root.as_bytes());
    let ephemeral_denomination_logic_witness =
        SimpleDenominationLogicWitness::generate_burned_ephemeral_witness(
            ephemeral_denomination_resource,
            ephemeral_denomination_existence_path,
            instant_nk,
            burn_signature,
            ephemeral_kudo_resource,
            ephemeral_kudo_existence_path,
            issuer,
            owner,
        );
    let ephemeral_denomination_info =
        SimpleDenominationInfo::new(ephemeral_denomination_logic_witness, None);

    let burn_info = Burn {
        burned_kudo: burned_kudo_info,
        burned_denomination: burned_denomination_info,
        ephemeral_kudo: ephemeral_kudo_info,
        ephemeral_denomination: ephemeral_denomination_info,
    };

    burn_info.create_tx()
}

#[test]
fn generate_a_burn_tx() {
    use std::time::Instant;

    let issuer_sk = AuthorizationSigningKey::new();
    let issuer = AuthorizationVerifyingKey::from_signing_key(&issuer_sk);
    // TODO: fix the kudo_logic
    let kudo_logic = KudoMainInfo::verifying_key_as_bytes();
    let kudo_lable = compute_kudo_label(&kudo_logic, &issuer);
    let owner_sk = issuer_sk.clone();
    let owner = AuthorizationVerifyingKey::from_signing_key(&owner_sk);
    let kudo_value = compute_kudo_value(&owner);
    let (kudo_nf_key, kudo_nk_cm) = NullifierKey::random_pair();
    let nonce = vec![0u8; 32]; // Use a fixed nonce for testing

    let kudo_resource = Resource::create(
        kudo_logic, kudo_lable, 100, kudo_value, false, nonce, kudo_nk_cm,
    );

    let tx_start_timer = Instant::now();
    let mut tx = build_burn_tx(
        &issuer_sk,
        &owner_sk,
        &kudo_resource,
        &kudo_nf_key,
        MerklePath::<COMMITMENT_TREE_DEPTH>::default(), // It should be a real path
    );

    tx.generate_delta_proof();
    println!("Tx build duration time: {:?}", tx_start_timer.elapsed());

    let tx_verify_start_timer = Instant::now();
    assert!(tx.verify());
    println!(
        "TX verify duration time: {:?}",
        tx_verify_start_timer.elapsed()
    );
}
