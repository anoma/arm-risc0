use aarm::logic_proof::{LogicProver, PaddingResourceLogic};
use aarm_core::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSignature, AuthorizationSigningKey, AuthorizationVerifyingKey},
    nullifier_key::{NullifierKey, NullifierKeyCommitment},
    resource::Resource,
};
use kudo_core::{
    kudo_logic_witness::KudoLogicWitness,
    receive_logic_witness::ReceiveLogicWitness,
    utils::{compute_kudo_label, compute_kudo_value},
};
// TODO: remove this dependency
use kudo_logic::KUDO_LOGIC_ID;
use kudo_tx::issue::IssueInstance;
use receive_logic::RECEIVE_ID;
use simple_denomination::{SimpleDenominationResourceLogic, SimpleDenominationWitness};

pub fn build_issue_tx(
    issuer_sk: &AuthorizationSigningKey,
    quantity: u128,
    receiver_pk: &AuthorizationVerifyingKey,
    receiver_signature: &AuthorizationSignature,
    receiver_nk_commitment: &NullifierKeyCommitment,
) -> IssueInstance<SimpleDenominationResourceLogic> {
    let issuer = AuthorizationVerifyingKey::from_signing_key(issuer_sk);
    let (instant_nk, instant_nk_commitment) = NullifierKey::random_pair();

    // Construct the issued kudo resource
    // TODO: fix the kudo_logic
    let kudo_lable = compute_kudo_label(&KUDO_LOGIC_ID.into(), &issuer);
    let kudo_value = compute_kudo_value(receiver_pk);
    let issued_kudo_resource = Resource::create(
        KUDO_LOGIC_ID.into(),
        kudo_lable,
        quantity,
        kudo_value,
        false,
        *receiver_nk_commitment,
    );
    let issued_kudo_resource_cm = issued_kudo_resource.commitment();

    // Construct the ephemeral kudo resource
    let ephemeral_kudo_resource = Resource::create(
        KUDO_LOGIC_ID.into(),
        kudo_lable,
        quantity,
        kudo_value,
        true,
        instant_nk_commitment,
    );
    let ephemeral_kudo_resource_nf = ephemeral_kudo_resource.nullifier(&instant_nk).unwrap();

    // Construct the issued denomination resource
    let denomination_logic = SimpleDenominationResourceLogic::verifying_key();
    let issued_denomination_resource = Resource::create(
        denomination_logic,
        [0u8; 32].into(), // TODO: fix the label?
        0,
        [0u8; 32].into(),
        true,
        instant_nk_commitment,
    );
    let issued_denomination_resource_cm = issued_denomination_resource.commitment();

    // Construct the issued receive logic resource
    let issued_receive_resource = Resource::create(
        RECEIVE_ID.into(),
        issued_kudo_resource_cm,
        0,
        [0u8; 32].into(),
        true,
        instant_nk_commitment,
    );
    let issued_receive_resource_nf = issued_receive_resource.nullifier(&instant_nk).unwrap();

    // Construct the ephemeral denomination resource
    let ephemeral_denomination_resource = Resource::create(
        denomination_logic,
        [0u8; 32].into(), // TODO: fix the label?
        0,
        [0u8; 32].into(),
        true,
        instant_nk_commitment,
    );
    let ephemeral_denomination_resource_cm = ephemeral_denomination_resource.commitment();

    // Construct the padding resource
    let padding_resource = PaddingResourceLogic::create_padding_resource(instant_nk_commitment);
    let padding_resource_nf = padding_resource.nullifier(&instant_nk).unwrap();

    // Construct the action tree
    let action_tree = MerkleTree::new(vec![
        ephemeral_kudo_resource_nf,
        issued_kudo_resource_cm,
        issued_receive_resource_nf,
        issued_denomination_resource_cm,
        padding_resource_nf,
        ephemeral_denomination_resource_cm,
    ]);
    let root = action_tree.root();

    // Generate paths
    let ephemeral_kudo_existence_path = action_tree
        .generate_path(ephemeral_kudo_resource_nf)
        .unwrap();
    let issued_kudo_existence_path = action_tree.generate_path(issued_kudo_resource_cm).unwrap();
    let issued_receive_existence_path = action_tree
        .generate_path(issued_receive_resource_nf)
        .unwrap();
    let issued_denomination_existence_path = action_tree
        .generate_path(issued_denomination_resource_cm)
        .unwrap();
    let padding_resource_existence_path = action_tree.generate_path(padding_resource_nf).unwrap();
    let ephemeral_denomination_existence_path = action_tree
        .generate_path(ephemeral_denomination_resource_cm)
        .unwrap();

    // Construct the issued kudo witness
    let issued_kudo_witness = KudoLogicWitness::generate_persistent_resource_creation_witness(
        issued_kudo_resource,
        issued_kudo_existence_path,
        issuer,
        issued_denomination_resource,
        issued_denomination_existence_path,
        instant_nk,
        false,
        issued_receive_resource,
        instant_nk,
        true,
        issued_receive_existence_path,
        *receiver_pk,
        *receiver_signature,
    );

    // Construct the denomination witness corresponding to the issued kudo resource
    let issue_denomination =
        SimpleDenominationWitness::generate_persistent_resource_creation_witness(
            issued_denomination_resource,
            issued_denomination_existence_path,
            false,
            instant_nk,
            issued_kudo_resource,
            issued_kudo_existence_path,
            issuer,
        )
        .into();

    // Construct the issued receive witness
    let issued_receive_witness = ReceiveLogicWitness::generate_witness(
        issued_receive_resource,
        issued_receive_existence_path,
        instant_nk,
        true,
        issued_kudo_resource,
        issued_kudo_existence_path,
    );

    // Construct the ephemeral kudo witness
    let ephemeral_kudo_witness = KudoLogicWitness::generate_consumed_ephemeral_witness(
        ephemeral_kudo_resource,
        ephemeral_kudo_existence_path,
        instant_nk,
        issuer,
        ephemeral_denomination_resource,
        ephemeral_denomination_existence_path,
    );

    // Construct the ephemeral denomination witness
    let signature = issuer_sk.sign(root.as_bytes());
    let ephemeral_denomination = SimpleDenominationWitness::generate_issued_ephemeral_witness(
        ephemeral_denomination_resource,
        ephemeral_denomination_existence_path,
        signature,
        ephemeral_kudo_resource,
        ephemeral_kudo_existence_path,
        instant_nk,
        issuer,
    )
    .into();

    // Construct the padding logic witness
    let padding_resource_logic = PaddingResourceLogic::new(
        padding_resource,
        padding_resource_existence_path,
        instant_nk,
        true,
    );

    IssueInstance {
        issued_kudo_witness,
        issue_denomination,
        issued_receive_witness,
        ephemeral_kudo_witness,
        ephemeral_denomination,
        padding_resource_logic,
    }
}

#[test]
fn generate_an_issue_tx() {
    use kudo_core::utils::generate_receive_signature;

    let (receiver_pk, receiver_signature) = {
        let sk = AuthorizationSigningKey::new();
        let pk = AuthorizationVerifyingKey::from_signing_key(&sk);
        let signature = generate_receive_signature(&RECEIVE_ID.into(), &sk);
        (pk, signature)
    };

    let issue_witness = build_issue_tx(
        &AuthorizationSigningKey::new(),
        100,
        &receiver_pk,
        &receiver_signature,
        &NullifierKeyCommitment::default(),
    );

    let mut tx = issue_witness.create_tx();
    tx.generate_delta_proof();

    assert!(tx.verify());
}
