use crate::{
    kudo_main::KudoMainInfo, simple_denomination::SimpleDenominationInfo,
    simple_receive::SimpleReceiveInfo,
};
use arm::{
    action::Action,
    authorization::{AuthorizationSignature, AuthorizationSigningKey, AuthorizationVerifyingKey},
    compliance_unit::ComplianceUnit,
    error::ArmError,
    logic_proof::{LogicProver, PaddingResourceLogic},
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
use kudo_traits::issue::Issue;
use rand::Rng;

pub fn build_issue_tx(
    issuer_sk: &AuthorizationSigningKey,
    quantity: u128,
    receiver_pk: &AuthorizationVerifyingKey,
    receiver_signature: &AuthorizationSignature,
    receiver_nk_commitment: &NullifierKeyCommitment,
    latest_root: Digest,
) -> Result<Transaction, ArmError> {
    let issuer = AuthorizationVerifyingKey::from_signing_key(issuer_sk);
    let (instant_nk, instant_nk_commitment) = NullifierKey::random_pair();
    let kudo_logic = KudoMainInfo::verifying_key();
    let kudo_lable = compute_kudo_label(&kudo_logic, &issuer);
    let kudo_value = compute_kudo_value(receiver_pk);

    // Construct the ephemeral kudo resource
    let mut rng = rand::thread_rng();
    let nonce: [u8; 32] = rng.gen(); // Random nonce for the ephemeral resource
    let ephemeral_kudo_resource = Resource::create(
        kudo_logic,
        kudo_lable,
        quantity,
        kudo_value,
        true,
        Digest::from(nonce),
        instant_nk_commitment,
    );
    let ephemeral_kudo_resource_nf = ephemeral_kudo_resource.nullifier(&instant_nk)?;

    // Construct the issued kudo resource
    let issued_kudo_resource = Resource::create(
        kudo_logic,
        kudo_lable,
        quantity,
        kudo_value,
        false,
        ephemeral_kudo_resource_nf,
        *receiver_nk_commitment,
    );
    let issued_kudo_resource_cm = issued_kudo_resource.commitment();

    // Construct the issued receive logic resource
    let nonce: [u8; 32] = rng.gen(); // Random nonce for the ephemeral resource
    let issued_receive_resource = Resource::create(
        SimpleReceiveInfo::verifying_key(),
        issued_kudo_resource_cm,
        0,
        Digest::default(),
        true,
        Digest::from(nonce),
        instant_nk_commitment,
    );
    let issued_receive_resource_nf = issued_receive_resource.nullifier(&instant_nk)?;

    // Construct the issued denomination resource
    let denomination_logic = SimpleDenominationInfo::verifying_key();
    let issued_denomination_resource = Resource::create(
        denomination_logic,
        issued_kudo_resource_cm, // Use the issued kudo commitment as the label
        0,
        Digest::default(),
        true,
        issued_receive_resource_nf,
        instant_nk_commitment,
    );
    let issued_denomination_resource_cm = issued_denomination_resource.commitment();

    // Construct the padding resource
    let padding_resource = PaddingResourceLogic::create_padding_resource(instant_nk_commitment);
    let padding_resource_nf = padding_resource.nullifier(&instant_nk)?;

    // Construct the ephemeral denomination resource
    let ephemeral_denomination_resource = Resource::create(
        denomination_logic,
        ephemeral_kudo_resource_nf, // Use the ephemeral kudo nullifier as the label
        0,
        Digest::default(), // Value is not used for ephemeral resources
        true,
        padding_resource_nf,
        instant_nk_commitment,
    );
    let ephemeral_denomination_resource_cm = ephemeral_denomination_resource.commitment();

    let action_tree = Action::<ComplianceUnit>::construct_action_tree(
        &[
            ephemeral_kudo_resource_nf,
            issued_receive_resource_nf,
            padding_resource_nf,
        ],
        &[
            issued_kudo_resource_cm,
            issued_denomination_resource_cm,
            ephemeral_denomination_resource_cm,
        ],
    );
    let root = action_tree.root();
    let root_bytes = root.as_bytes();

    // Generate paths
    let ephemeral_kudo_existence_path = action_tree.generate_path(&ephemeral_kudo_resource_nf)?;
    let issued_kudo_existence_path = action_tree.generate_path(&issued_kudo_resource_cm)?;
    let issued_receive_existence_path = action_tree.generate_path(&issued_receive_resource_nf)?;
    let issued_denomination_existence_path =
        action_tree.generate_path(&issued_denomination_resource_cm)?;
    let padding_resource_existence_path = action_tree.generate_path(&padding_resource_nf)?;
    let ephemeral_denomination_existence_path =
        action_tree.generate_path(&ephemeral_denomination_resource_cm)?;

    // Construct the issued kudo witness
    let issue_kudo_logic_witness = KudoMainWitness::generate_persistent_resource_creation_witness(
        issued_kudo_resource,
        issued_kudo_existence_path.clone(),
        issuer,
        issued_denomination_resource,
        issued_denomination_existence_path.clone(),
        instant_nk.clone(),
        false,
        issued_receive_resource,
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
            issued_denomination_resource,
            issued_denomination_existence_path.clone(),
            false,
            instant_nk.clone(),
            issued_kudo_resource,
            issued_kudo_existence_path.clone(),
            issuer,
        );
    let issue_denomination = SimpleDenominationInfo::new(issue_denomination_logic_witness, None);

    // Construct the issued receive witness
    let issue_receive_logic_witness = SimpleReceiveLogicWitness::generate_witness(
        issued_receive_resource,
        issued_receive_existence_path.clone(),
        instant_nk.clone(),
        true,
        issued_kudo_resource,
        issued_kudo_existence_path.clone(),
    );
    let issue_receive = SimpleReceiveInfo::new(issue_receive_logic_witness, None);

    // Construct the ephemeral kudo witness
    let ephemeral_kudo_logic_witness = KudoMainWitness::generate_consumed_ephemeral_witness(
        ephemeral_kudo_resource,
        ephemeral_kudo_existence_path.clone(),
        instant_nk.clone(),
        issuer,
        ephemeral_denomination_resource,
        ephemeral_denomination_existence_path.clone(),
    );
    let ephemeral_kudo = KudoMainInfo::new(ephemeral_kudo_logic_witness, None);

    // Construct the ephemeral denomination witness
    let signature = issuer_sk.sign(root_bytes);
    let ephemeral_denomination_logic_witness =
        SimpleDenominationLogicWitness::generate_issued_ephemeral_witness(
            ephemeral_denomination_resource,
            ephemeral_denomination_existence_path.clone(),
            signature,
            ephemeral_kudo_resource,
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

    issue.create_tx(latest_root)
}

#[test]
fn generate_an_issue_tx() {
    use arm::compliance::INITIAL_ROOT;
    use kudo_logic_witness::utils::generate_receive_signature;
    use std::time::Instant;

    let (receiver_pk, receiver_signature) = {
        let sk = AuthorizationSigningKey::new();
        let pk = AuthorizationVerifyingKey::from_signing_key(&sk);
        let signature =
            generate_receive_signature(&SimpleReceiveInfo::verifying_key_as_bytes(), &sk);
        (pk, signature)
    };

    let tx_start_timer = Instant::now();
    let tx = build_issue_tx(
        &AuthorizationSigningKey::new(),
        100,
        &receiver_pk,
        &receiver_signature,
        &NullifierKeyCommitment::default(),
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
