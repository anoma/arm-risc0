use crate::{
    kudo_main::KudoMainInfo, simple_denomination::SimpleDenominationInfo,
    simple_receive::SimpleReceiveInfo,
};
use arm::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSignature, AuthorizationSigningKey, AuthorizationVerifyingKey},
    error::ArmError,
    logic_proof::{LogicProver, PaddingResourceLogic},
    merkle_path::MerklePath,
    nullifier_key::{NullifierKey, NullifierKeyCommitment},
    resource::Resource,
    transaction::Transaction,
    Digest,
};
use kudo_logic_witness::{
    kudo_main_witness::KudoMainWitness,
    simple_denomination_witness::SimpleDenominationLogicWitness,
    simple_receive_witness::SimpleReceiveLogicWitness,
    utils::{compute_kudo_label, compute_kudo_value},
};
use kudo_traits::transfer::Transfer;
use rand::Rng;

#[allow(clippy::too_many_arguments)]
pub fn build_transfer_tx(
    issuer: &AuthorizationVerifyingKey,
    owner_sk: &AuthorizationSigningKey,
    consumed_kudo_resource: &Resource,
    consumed_kudo_nf_key: &NullifierKey,
    consumed_kudo_path: MerklePath,
    receiver_pk: &AuthorizationVerifyingKey,
    receiver_signature: &AuthorizationSignature,
    receiver_nk_commitment: &NullifierKeyCommitment,
    latest_root: Digest,
) -> Result<Transaction, ArmError> {
    let (instant_nk, instant_nk_commitment) = NullifierKey::random_pair();

    // Construct the consumed kudo resource
    let kudo_logic = KudoMainInfo::verifying_key_as_bytes();
    let kudo_lable = compute_kudo_label(&kudo_logic, issuer);
    assert_eq!(consumed_kudo_resource.label_ref, kudo_lable);
    let owner = AuthorizationVerifyingKey::from_signing_key(owner_sk);
    let kudo_value = compute_kudo_value(&owner);
    assert_eq!(kudo_value, consumed_kudo_resource.value_ref);
    let consumed_kudo_nf = consumed_kudo_resource.nullifier(consumed_kudo_nf_key)?;

    // Construct the created kudo resource
    let mut created_kudo_resource = consumed_kudo_resource.clone();
    // Set the new ownership to the created kudo resource
    created_kudo_resource.set_nf_commitment(receiver_nk_commitment.clone());
    let created_kudo_value = compute_kudo_value(receiver_pk);
    created_kudo_resource.set_value_ref(created_kudo_value);
    // Reset the randomness and nonce
    created_kudo_resource.reset_randomness();
    created_kudo_resource.set_nonce(consumed_kudo_nf.as_bytes().to_vec());
    let created_kudo_cm = created_kudo_resource.commitment();

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
    let consumed_denomination_resource_nf =
        consumed_denomination_resource.nullifier(&instant_nk)?;

    // Construct the denomination resource corresponding to the created kudo resource
    let created_denomination_resource = Resource::create(
        denomination_logic.clone(),
        created_kudo_cm.as_bytes().to_vec(), // Use the created kudo commitment as the label
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
    let padding_resource_nf = padding_resource.nullifier(&instant_nk)?;

    // Construct the receive logic resource
    let receive_resource = Resource::create(
        SimpleReceiveInfo::verifying_key_as_bytes(),
        created_kudo_cm.as_bytes().to_vec(),
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
        created_kudo_cm,
        consumed_denomination_resource_nf,
        created_denomination_resource_cm,
        padding_resource_nf,
        receive_resource_cm,
    ]);
    let root = action_tree.root();
    let root_bytes = root.as_bytes();

    // Generate paths
    let consumed_kudo_existence_path = action_tree.generate_path(&consumed_kudo_nf)?;
    let consumed_denomination_existence_path =
        action_tree.generate_path(&consumed_denomination_resource_nf)?;
    let created_denomination_existence_path =
        action_tree.generate_path(&created_denomination_resource_cm)?;
    let created_kudo_existence_path = action_tree.generate_path(&created_kudo_cm)?;
    let padding_resource_existence_path = action_tree.generate_path(&padding_resource_nf)?;
    let receive_existence_path = action_tree.generate_path(&receive_resource_cm)?;

    // Construct the consumed kudo witness
    let consumed_kudo_logic_witness =
        KudoMainWitness::generate_persistent_resource_consumption_witness(
            consumed_kudo_resource.clone(),
            consumed_kudo_existence_path.clone(),
            consumed_kudo_nf_key.clone(),
            *issuer,
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
            consumed_kudo_nf_key.clone(),
            *issuer,
            owner,
        );
    let consumed_denomination =
        SimpleDenominationInfo::new(consumed_denomination_logic_witness, None);

    // Construct the created kudo witness
    let created_kudo_logic_witness = KudoMainWitness::generate_persistent_resource_creation_witness(
        created_kudo_resource.clone(),
        created_kudo_existence_path.clone(),
        *issuer,
        created_denomination_resource.clone(),
        created_denomination_existence_path.clone(),
        NullifierKey::default(), // Not used in this case
        false,
        receive_resource.clone(),
        NullifierKey::default(), // Not used in this case
        false,
        receive_existence_path.clone(),
        *receiver_pk,
        *receiver_signature,
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
            *issuer,
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

    let transfer = Transfer {
        consumed_kudo,
        consumed_denomination,
        created_kudo,
        created_denomination,
        padding_resource_logic,
        created_receive,
    };

    transfer.create_tx(latest_root)
}

#[test]
fn generate_a_transfer_tx() {
    use arm::compliance::INITIAL_ROOT;
    use kudo_logic_witness::utils::generate_receive_signature;
    use std::time::Instant;

    let kudo_logic = KudoMainInfo::verifying_key_as_bytes();
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
        let signature =
            generate_receive_signature(&SimpleReceiveInfo::verifying_key_as_bytes(), &sk);
        (pk, signature)
    };
    let (_receiver_nf_key, receiver_nk_commitment) = NullifierKey::random_pair();
    let nonce = vec![0u8; 32]; // Random nonce for the ephemeral resource

    let consumed_kudo_resource = Resource::create(
        kudo_logic, kudo_lable, 100, kudo_value, false, nonce, kudo_nk_cm,
    );

    let tx_start_timer = Instant::now();
    let tx = build_transfer_tx(
        &issuer,
        &owner_sk,
        &consumed_kudo_resource,
        &kudo_nf_key,
        MerklePath::default(), // It should be a real path
        &receiver_pk,
        &receiver_signature,
        &receiver_nk_commitment,
        *INITIAL_ROOT,
    )
    .unwrap();

    let balanced_tx = tx.generate_delta_proof().unwrap();
    println!("Tx build duration time: {:?}", tx_start_timer.elapsed());

    let tx_verify_start_timer = Instant::now();
    balanced_tx.verify().unwrap();
    println!(
        "TX verify duration time: {:?}",
        tx_verify_start_timer.elapsed()
    );
}
