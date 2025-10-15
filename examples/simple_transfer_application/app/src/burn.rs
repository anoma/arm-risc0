use arm::{
    action::Action,
    action_tree::MerkleTree,
    authorization::{AuthorizationSignature, AuthorizationVerifyingKey},
    compliance::ComplianceWitness,
    compliance_unit::ComplianceUnit,
    delta_proof::DeltaWitness,
    error::ArmError,
    logic_proof::LogicProver,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    transaction::{Delta, Transaction},
};

use crate::TransferLogic;

#[allow(clippy::too_many_arguments)]
pub fn construct_burn_tx(
    consumed_resource: Resource,
    consumed_resource_path: MerklePath,
    consumed_nf_key: NullifierKey,
    consumed_auth_pk: AuthorizationVerifyingKey,
    consumed_auth_sig: AuthorizationSignature,
    created_resource: Resource,
    forwarder_addr: Vec<u8>,
    token_addr: Vec<u8>,
    user_addr: Vec<u8>,
) -> Result<Transaction, ArmError> {
    // Action tree
    let consumed_nf = consumed_resource.nullifier(&consumed_nf_key)?;
    let created_cm = created_resource.commitment();
    let action_tree_root = MerkleTree::new(vec![consumed_nf, created_cm]).root();

    // Generate compliance units
    let compliance_witness = ComplianceWitness::from_resources_with_path(
        consumed_resource,
        consumed_nf_key.clone(),
        consumed_resource_path,
        created_resource,
    );
    let compliance_unit = ComplianceUnit::create(&compliance_witness)?;

    // Generate logic proofs
    let consumed_resource_logic = TransferLogic::consume_persistent_resource_logic(
        consumed_resource,
        action_tree_root,
        consumed_nf_key,
        consumed_auth_pk,
        consumed_auth_sig,
    );
    let consumed_logic_proof = consumed_resource_logic.prove()?;

    let created_resource_logic = TransferLogic::burn_resource_logic(
        created_resource,
        action_tree_root,
        forwarder_addr,
        token_addr,
        user_addr,
    );
    let created_logic_proof = created_resource_logic.prove()?;

    // Construct the action
    let action = Action::new(
        vec![compliance_unit],
        vec![consumed_logic_proof, created_logic_proof],
    )?;

    // Construct the transaction
    let delta_witness = DeltaWitness::from_bytes(&compliance_witness.rcv)?;
    let tx = Transaction::create(vec![action], Delta::Witness(delta_witness));
    let balanced_tx = tx.generate_delta_proof().unwrap();
    Ok(balanced_tx)
}

#[test]
fn simple_burn_test() {
    use crate::{
        resource::{construct_ephemeral_resource, construct_persistent_resource},
        utils::authorize_the_action,
    };
    use arm::{
        action_tree::MerkleTree,
        authorization::{AuthorizationSigningKey, AuthorizationVerifyingKey},
        merkle_path::MerklePath,
        nullifier_key::NullifierKey,
    };

    let forwarder_addr = vec![1u8; 20];
    let token_addr = vec![2u8; 20];
    let user_addr = vec![3u8; 20];
    let quantity = 100;

    // Obtain the consumed resource data
    let consumed_auth_sk = AuthorizationSigningKey::new();
    let consumed_auth_pk = AuthorizationVerifyingKey::from_signing_key(&consumed_auth_sk);
    let (consumed_nf_key, consumed_nf_cm) = NullifierKey::random_pair();
    let consumed_resource = construct_persistent_resource(
        &forwarder_addr, // forwarder_addr
        &token_addr,     // token_addr
        quantity,
        [4u8; 32], // nonce
        consumed_nf_cm,
        [5u8; 32], // rand_seed
        &consumed_auth_pk,
    );
    let consumed_nf = consumed_resource.nullifier(&consumed_nf_key).unwrap();

    // Create the ephemeral resource
    let (_created_nf_key, created_nf_cm) = NullifierKey::random_pair();
    let created_resource = construct_ephemeral_resource(
        &forwarder_addr, // forwarder_addr
        &token_addr,     // token_addr
        quantity,
        consumed_nf.as_bytes().try_into().unwrap(), // nonce
        created_nf_cm,
        [6u8; 32],  // rand_seed
        &user_addr, // user_addr
    );
    let created_cm = created_resource.commitment();

    // Get the authorization signature, it can be from external signing(e.g. wallet)
    let action_tree = MerkleTree::new(vec![consumed_nf, created_cm]);
    let auth_sig = authorize_the_action(&consumed_auth_sk, &action_tree);

    // Construct the burn transaction
    let merkle_path = MerklePath::default(); // mock a path
    let tx_start_timer = std::time::Instant::now();
    let tx = construct_burn_tx(
        consumed_resource,
        merkle_path,
        consumed_nf_key,
        consumed_auth_pk,
        auth_sig,
        created_resource,
        forwarder_addr,
        token_addr,
        user_addr,
    )
    .unwrap();
    println!("Tx build duration time: {:?}", tx_start_timer.elapsed());

    // Verify the transaction
    tx.verify().unwrap();
}
