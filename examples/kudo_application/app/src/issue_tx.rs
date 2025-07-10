use crate::{
    kudo_main::KudoMainInfo, simple_denomination::SimpleDenominationInfo,
    simple_receive::SimpleReceiveInfo,
};
use arm::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSignature, AuthorizationSigningKey, AuthorizationVerifyingKey},
    nullifier_key::{NullifierKey, NullifierKeyCommitment},
    resource::Resource,
};
use arm::{
    logic_proof::{LogicProver, PaddingResourceLogic},
    transaction::Transaction,
};
use kudo_logic_witness::{
    kudo_main_witness::KudoMainWitness,
    simple_denomination_witness::SimpleDenominationLogicWitness,
    simple_receive_witness::SimpleReceiveLogicWitness,
    utils::{compute_kudo_label, compute_kudo_value},
};
use kudo_traits::issue::Issue;
use rand::Rng;

pub fn build_issue_tx(
    issuer_sk: &AuthorizationSigningKey,
    quantity: u128,
    receiver_pk: &AuthorizationVerifyingKey,
    receiver_signature: &AuthorizationSignature,
    receiver_nk_commitment: &NullifierKeyCommitment,
) -> Transaction {
    let issuer = AuthorizationVerifyingKey::from_signing_key(issuer_sk);
    let (instant_nk, instant_nk_commitment) = NullifierKey::random_pair();
    let kudo_logic = KudoMainInfo::verifying_key();
    let kudo_lable = compute_kudo_label(&kudo_logic, &issuer);
    let kudo_value = compute_kudo_value(receiver_pk);

    // Construct the ephemeral kudo resource
    let mut rng = rand::thread_rng();
    let nonce: [u8; 32] = rng.gen(); // Random nonce for the ephemeral resource
    let ephemeral_kudo_resource = Resource::create(
        kudo_logic.clone(),
        kudo_lable.clone(),
        quantity,
        kudo_value.clone(),
        true,
        nonce.to_vec(),
        instant_nk_commitment.clone(),
    );
    let ephemeral_kudo_resource_nf = ephemeral_kudo_resource.nullifier(&instant_nk).unwrap();

    // Construct the issued kudo resource
    let issued_kudo_resource = Resource::create(
        kudo_logic,
        kudo_lable,
        quantity,
        kudo_value,
        false,
        ephemeral_kudo_resource_nf.clone(),
        receiver_nk_commitment.clone(),
    );
    let issued_kudo_resource_cm = issued_kudo_resource.commitment();

    // Construct the issued receive logic resource
    let nonce: [u8; 32] = rng.gen(); // Random nonce for the ephemeral resource
    let issued_receive_resource = Resource::create(
        SimpleReceiveInfo::verifying_key(),
        issued_kudo_resource_cm.clone(),
        0,
        [0u8; 32].into(),
        true,
        nonce.to_vec(),
        instant_nk_commitment.clone(),
    );
    let issued_receive_resource_nf = issued_receive_resource.nullifier(&instant_nk).unwrap();

    // Construct the issued denomination resource
    let denomination_logic = SimpleDenominationInfo::verifying_key();
    let issued_denomination_resource = Resource::create(
        denomination_logic.clone(),
        issued_kudo_resource_cm.clone(), // Use the issued kudo commitment as the label
        0,
        [0u8; 32].into(),
        true,
        issued_receive_resource_nf.clone(),
        instant_nk_commitment.clone(),
    );
    let issued_denomination_resource_cm = issued_denomination_resource.commitment();

    // Construct the padding resource
    let padding_resource =
        PaddingResourceLogic::create_padding_resource(instant_nk_commitment.clone());
    let padding_resource_nf = padding_resource.nullifier(&instant_nk).unwrap();

    // Construct the ephemeral denomination resource
    let ephemeral_denomination_resource = Resource::create(
        denomination_logic,
        ephemeral_kudo_resource_nf.clone(), // Use the ephemeral kudo nullifier as the label
        0,
        [0u8; 32].into(),
        true,
        padding_resource_nf.clone(),
        instant_nk_commitment.clone(),
    );
    let ephemeral_denomination_resource_cm = ephemeral_denomination_resource.commitment();

    // Construct the action tree
    let action_tree = MerkleTree::new(vec![
        ephemeral_kudo_resource_nf.clone().into(),
        issued_kudo_resource_cm.clone().into(),
        issued_receive_resource_nf.clone().into(),
        issued_denomination_resource_cm.clone().into(),
        padding_resource_nf.clone().into(),
        ephemeral_denomination_resource_cm.clone().into(),
    ]);
    let root = action_tree.root();

    // Generate paths
    let ephemeral_kudo_existence_path = action_tree
        .generate_path(&ephemeral_kudo_resource_nf)
        .unwrap();
    let issued_kudo_existence_path = action_tree.generate_path(&issued_kudo_resource_cm).unwrap();
    let issued_receive_existence_path = action_tree
        .generate_path(&issued_receive_resource_nf)
        .unwrap();
    let issued_denomination_existence_path = action_tree
        .generate_path(&issued_denomination_resource_cm)
        .unwrap();
    let padding_resource_existence_path = action_tree.generate_path(&padding_resource_nf).unwrap();
    let ephemeral_denomination_existence_path = action_tree
        .generate_path(&ephemeral_denomination_resource_cm)
        .unwrap();

    // Construct the issued kudo witness
    let issue_kudo_logic_witness = KudoMainWitness::generate_persistent_resource_creation_witness(
        issued_kudo_resource.clone(),
        issued_kudo_existence_path.clone(),
        issuer,
        issued_denomination_resource.clone(),
        issued_denomination_existence_path.clone(),
        instant_nk.clone(),
        false,
        issued_receive_resource.clone(),
        instant_nk.clone(),
        true,
        issued_receive_existence_path.clone(),
        *receiver_pk,
        *receiver_signature,
    );
    let issue_kudo = KudoMainInfo::new(issue_kudo_logic_witness, None);

    // Construct the denomination witness corresponding to the issued kudo resource
    let issue_denomination_logic_witness =
        SimpleDenominationLogicWitness::generate_created_kudo_denomination_witness(
            issued_denomination_resource.clone(),
            issued_denomination_existence_path.clone(),
            false,
            instant_nk.clone(),
            issued_kudo_resource.clone(),
            issued_kudo_existence_path.clone(),
            issuer,
        );
    let issue_denomination = SimpleDenominationInfo::new(issue_denomination_logic_witness, None);

    // Construct the issued receive witness
    let issue_receive_logic_witness = SimpleReceiveLogicWitness::generate_witness(
        issued_receive_resource.clone(),
        issued_receive_existence_path.clone(),
        instant_nk.clone(),
        true,
        issued_kudo_resource.clone(),
        issued_kudo_existence_path.clone(),
    );
    let issue_receive = SimpleReceiveInfo::new(issue_receive_logic_witness, None);

    // Construct the ephemeral kudo witness
    let ephemeral_kudo_logic_witness = KudoMainWitness::generate_consumed_ephemeral_witness(
        ephemeral_kudo_resource.clone(),
        ephemeral_kudo_existence_path.clone(),
        instant_nk.clone(),
        issuer,
        ephemeral_denomination_resource.clone(),
        ephemeral_denomination_existence_path.clone(),
    );
    let ephemeral_kudo = KudoMainInfo::new(ephemeral_kudo_logic_witness, None);

    // Construct the ephemeral denomination witness
    let signature = issuer_sk.sign(&root);
    let ephemeral_denomination_logic_witness =
        SimpleDenominationLogicWitness::generate_issued_ephemeral_witness(
            ephemeral_denomination_resource.clone(),
            ephemeral_denomination_existence_path.clone(),
            signature,
            ephemeral_kudo_resource.clone(),
            ephemeral_kudo_existence_path.clone(),
            instant_nk.clone(),
            issuer,
        );
    let ephemeral_denomination =
        SimpleDenominationInfo::new(ephemeral_denomination_logic_witness, None);

    // Construct the padding logic witness
    let padding_resource_logic = PaddingResourceLogic::new(
        padding_resource,
        padding_resource_existence_path,
        instant_nk.clone(),
        true,
    );

    let issue = Issue {
        issue_kudo,
        issue_denomination,
        issue_receive,
        ephemeral_kudo,
        ephemeral_denomination,
        padding_resource_logic,
    };

    issue.create_tx()
}

#[test]
fn generate_an_issue_tx() {
    use kudo_logic_witness::utils::generate_receive_signature;
    use std::time::Instant;

    let (receiver_pk, receiver_signature) = {
        let sk = AuthorizationSigningKey::new();
        let pk = AuthorizationVerifyingKey::from_signing_key(&sk);
        let signature = generate_receive_signature(&SimpleReceiveInfo::verifying_key(), &sk);
        (pk, signature)
    };

    let tx_start_timer = Instant::now();
    let mut tx = build_issue_tx(
        &AuthorizationSigningKey::new(),
        100,
        &receiver_pk,
        &receiver_signature,
        &NullifierKeyCommitment::default(),
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
