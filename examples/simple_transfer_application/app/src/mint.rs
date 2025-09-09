use arm::{
    action::Action,
    action_tree::MerkleTree,
    compliance::ComplianceWitness,
    compliance_unit::ComplianceUnit,
    delta_proof::DeltaWitness,
    encryption::AffinePoint,
    logic_proof::LogicProver,
    nullifier_key::NullifierKey,
    resource::Resource,
    transaction::{Delta, Transaction},
};

use crate::TransferLogic;

#[allow(clippy::too_many_arguments)]
pub fn construct_mint_tx(
    consumed_resource: Resource,
    latest_cm_tree_root: Vec<u32>,
    consumed_nf_key: NullifierKey,
    consumed_discovery_pk: AffinePoint,
    forwarder_addr: Vec<u8>,
    token_addr: Vec<u8>,
    user_addr: Vec<u8>,
    permit_nonce: Vec<u8>,
    permit_deadline: Vec<u8>,
    permit_sig: Vec<u8>,
    created_resource: Resource,
    created_discovery_pk: AffinePoint,
    created_encryption_pk: AffinePoint,
) -> Transaction {
    // Action tree
    let consumed_nf = consumed_resource.nullifier(&consumed_nf_key).unwrap();
    let created_cm = created_resource.commitment();
    let action_tree = MerkleTree::new(vec![consumed_nf, created_cm]);

    // Generate compliance units
    let compliance_witness = ComplianceWitness::from_resources(
        consumed_resource.clone(),
        latest_cm_tree_root,
        consumed_nf_key.clone(),
        created_resource.clone(),
    );
    let compliance_unit = ComplianceUnit::create(&compliance_witness);

    // Generate logic proofs
    let consumed_resource_path = action_tree.generate_path(&consumed_nf).unwrap();
    let consumed_resource_logic = TransferLogic::mint_resource_logic_with_permit(
        consumed_resource,
        consumed_resource_path,
        consumed_nf_key,
        consumed_discovery_pk,
        forwarder_addr.clone(),
        token_addr.clone(),
        user_addr.clone(),
        permit_nonce,
        permit_deadline,
        permit_sig,
    );
    let consumed_logic_proof = consumed_resource_logic.prove();

    let created_resource_path = action_tree.generate_path(&created_cm).unwrap();
    let created_resource_logic = TransferLogic::create_persistent_resource_logic(
        created_resource,
        created_resource_path,
        created_discovery_pk,
        created_encryption_pk,
    );
    let created_logic_proof = created_resource_logic.prove();

    // Construct the action
    let action = Action::new(
        vec![compliance_unit],
        vec![consumed_logic_proof, created_logic_proof],
    );

    // Construct the transaction
    let delta_witness = DeltaWitness::from_bytes(&compliance_witness.rcv);
    let mut tx = Transaction::create(vec![action], Delta::Witness(delta_witness));
    tx.generate_delta_proof();
    tx
}

#[test]
fn simple_mint_test() {
    use crate::resource::{construct_ephemeral_resource, construct_persistent_resource};
    use arm::{
        authorization::{AuthorizationSigningKey, AuthorizationVerifyingKey},
        compliance::INITIAL_ROOT,
        encryption::random_keypair,
        evm::CallType,
        nullifier_key::NullifierKey,
    };

    let forwarder_addr = vec![1u8; 20];
    let token_addr = vec![2u8; 20];
    let user_addr = vec![3u8; 20];
    let quantity = 100;

    // Construct the consumed resource
    let (consumed_nf_key, consumed_nf_cm) = NullifierKey::random_pair();
    let consumed_resource = construct_ephemeral_resource(
        &forwarder_addr,
        &token_addr,
        quantity,
        vec![4u8; 32], // nonce
        consumed_nf_cm,
        vec![5u8; 32], // rand_seed
        CallType::Wrap,
        &user_addr,
    );
    let consumed_nf = consumed_resource.nullifier(&consumed_nf_key).unwrap();
    // Fetch the latest cm tree root from the chain
    let latest_cm_tree_root = INITIAL_ROOT.as_words().to_vec();

    // Generate the created resource
    let (_created_nf_key, created_nf_cm) = NullifierKey::random_pair();
    let created_auth_sk = AuthorizationSigningKey::new();
    let created_auth_pk = AuthorizationVerifyingKey::from_signing_key(&created_auth_sk);
    let (_created_discovery_sk, created_discovery_pk) = random_keypair();
    let (_created_encryption_sk, created_encryption_pk) = random_keypair();
    let created_resource = construct_persistent_resource(
        &forwarder_addr,
        &token_addr,
        quantity,
        consumed_nf.as_bytes().to_vec(), // nonce
        created_nf_cm,
        vec![6u8; 32], // rand_seed
        &created_auth_pk,
    );

    // Fetch the permit signature from the somewhere
    let permit_nonce = vec![7u8; 32];
    let permit_deadline = vec![8u8; 32];
    let permit_sig = vec![9u8; 65];

    // Construct the mint transaction
    let tx = construct_mint_tx(
        consumed_resource,
        latest_cm_tree_root,
        consumed_nf_key,
        created_discovery_pk,
        forwarder_addr,
        token_addr,
        user_addr,
        permit_nonce,
        permit_deadline,
        permit_sig,
        created_resource,
        created_discovery_pk,
        created_encryption_pk,
    );

    // Verify the transaction
    assert!(tx.verify(), "Transaction verification failed");
}
