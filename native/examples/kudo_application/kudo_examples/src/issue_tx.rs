use aarm::logic_proof::{LogicProver, PaddingResourceLogic};
use aarm_core::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSignature, AuthorizationSigningKey, AuthorizationVerifyingKey},
    nullifier_key::{NullifierKey, NullifierKeyCommitment},
    resource::Resource,
};
use kudo_core::utils::{compute_kudo_label, compute_kudo_value};
use kudo_resource::{KudoResourceLogic, KudoResourceLogicWitness};
use kudo_tx::issue::IssueInstance;
use simple_denomination::{SimpleDenominationResourceLogic, SimpleDenominationWitness};
use simple_receive::{SimpleReceiveLogic, SimpleReceiveWitness};

pub fn build_issue_tx(
    issuer_sk: &AuthorizationSigningKey,
    quantity: u128,
    receiver_pk: &AuthorizationVerifyingKey,
    receiver_signature: &AuthorizationSignature,
    receiver_nk_commitment: &NullifierKeyCommitment,
) -> IssueInstance<KudoResourceLogic, SimpleDenominationResourceLogic, SimpleReceiveLogic> {
    let issuer = AuthorizationVerifyingKey::from_signing_key(issuer_sk);
    let (instant_nk, instant_nk_commitment) = NullifierKey::random_pair();

    // Construct the issued kudo resource
    let kudo_logic = KudoResourceLogic::verifying_key();
    let kudo_lable = compute_kudo_label(&kudo_logic, &issuer);
    let kudo_value = compute_kudo_value(receiver_pk);
    let issued_kudo_resource = Resource::create(
        kudo_logic,
        kudo_lable,
        quantity,
        kudo_value,
        false,
        *receiver_nk_commitment,
    );
    let issued_kudo_resource_cm = issued_kudo_resource.commitment();

    // Construct the ephemeral kudo resource
    let ephemeral_kudo_resource = Resource::create(
        kudo_logic,
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
        SimpleReceiveLogic::verifying_key(),
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
    let issue_kudo = KudoResourceLogicWitness::generate_persistent_resource_creation_witness(
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
    )
    .into();

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
    let issue_receive = SimpleReceiveWitness::generate_witness(
        issued_receive_resource,
        issued_receive_existence_path,
        instant_nk,
        true,
        issued_kudo_resource,
        issued_kudo_existence_path,
    )
    .into();

    // Construct the ephemeral kudo witness
    let ephemeral_kudo = KudoResourceLogicWitness::generate_consumed_ephemeral_witness(
        ephemeral_kudo_resource,
        ephemeral_kudo_existence_path,
        instant_nk,
        issuer,
        ephemeral_denomination_resource,
        ephemeral_denomination_existence_path,
    )
    .into();

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
        issue_kudo,
        issue_denomination,
        issue_receive,
        ephemeral_kudo,
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
        let signature = generate_receive_signature(&SimpleReceiveLogic::verifying_key(), &sk);
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
