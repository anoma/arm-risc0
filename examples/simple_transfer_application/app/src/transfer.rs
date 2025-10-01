use crate::TransferLogic;
use arm::{
    action::Action,
    action_tree::MerkleTree,
    authorization::{AuthorizationSignature, AuthorizationVerifyingKey},
    compliance::ComplianceWitness,
    compliance_unit::ComplianceUnit,
    delta_proof::DeltaWitness,
    encryption::AffinePoint,
    error::ArmError,
    logic_proof::LogicProver,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    transaction::{Delta, Transaction},
};

#[allow(clippy::too_many_arguments)]
pub fn construct_transfer_tx(
    consumed_resource: Resource,
    consumed_resource_path: MerklePath,
    consumed_nf_key: NullifierKey,
    consumed_auth_pk: AuthorizationVerifyingKey,
    consumed_auth_sig: AuthorizationSignature,
    created_resource: Resource,
    created_discovery_pk: AffinePoint,
    created_encryption_pk: AffinePoint,
) -> Result<Transaction, ArmError> {
    // Action tree
    let consumed_nf = consumed_resource.nullifier(&consumed_nf_key)?;
    let created_cm = created_resource.commitment();
    let action_tree = MerkleTree::new(vec![consumed_nf, created_cm]);

    // Generate compliance units
    let compliance_witness = ComplianceWitness::from_resources_with_path(
        consumed_resource,
        consumed_nf_key.clone(),
        consumed_resource_path,
        created_resource,
    );
    let compliance_unit = ComplianceUnit::create(&compliance_witness)?;

    // Generate logic proofs
    let consumed_resource_path = action_tree.generate_path(&consumed_nf)?;
    let consumed_resource_logic = TransferLogic::consume_persistent_resource_logic(
        consumed_resource,
        consumed_resource_path,
        consumed_nf_key,
        consumed_auth_pk,
        consumed_auth_sig,
    );
    let consumed_logic_proof = consumed_resource_logic.prove()?;

    let created_resource_path = action_tree.generate_path(&created_cm)?;
    let created_resource_logic = TransferLogic::create_persistent_resource_logic(
        created_resource,
        created_resource_path,
        &created_discovery_pk,
        created_encryption_pk,
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
fn simple_transfer_test() {
    use crate::{resource::construct_persistent_resource, utils::authorize_the_action};
    use arm::{
        action_tree::MerkleTree,
        authorization::{AuthorizationSigningKey, AuthorizationVerifyingKey},
        encryption::{random_keypair, Ciphertext},
        merkle_path::MerklePath,
        nullifier_key::NullifierKey,
    };

    let forwarder_addr = vec![1u8; 20];
    let token_addr = vec![2u8; 20];
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

    // Create the created resource data
    let created_auth_sk = AuthorizationSigningKey::new();
    let created_auth_pk = AuthorizationVerifyingKey::from_signing_key(&created_auth_sk);
    let (_created_nf_key, created_nf_cm) = NullifierKey::random_pair();
    let (created_discovery_sk, created_discovery_pk) = random_keypair();
    let (created_encryption_sk, created_encryption_pk) = random_keypair();
    let created_resource = construct_persistent_resource(
        &forwarder_addr, // forwarder_addr
        &token_addr,     // token_addr
        quantity,
        consumed_nf.as_bytes().try_into().unwrap(), // nonce
        created_nf_cm,
        [7u8; 32], // rand_seed
        &created_auth_pk,
    );
    let created_cm = created_resource.commitment();

    // Get the authorization signature, it can be from external signing(e.g. wallet)
    let action_tree = MerkleTree::new(vec![consumed_nf, created_cm]);
    let auth_sig = authorize_the_action(&consumed_auth_sk, &action_tree);

    // Construct the transfer transaction
    let merkle_path = MerklePath::default(); // mock a path

    let tx_start_timer = std::time::Instant::now();
    let tx = construct_transfer_tx(
        consumed_resource,
        merkle_path.clone(),
        consumed_nf_key.clone(),
        consumed_auth_pk,
        auth_sig,
        created_resource,
        created_discovery_pk,
        created_encryption_pk,
    )
    .unwrap();
    println!("Tx build duration time: {:?}", tx_start_timer.elapsed());

    // check the discovery ciphertexts
    let discovery_ciphertext = Ciphertext::from_words(
        &tx.actions[0].logic_verifier_inputs[1]
            .app_data
            .discovery_payload[0]
            .blob,
    );
    discovery_ciphertext.decrypt(&created_discovery_sk).unwrap();

    // check the encryption ciphertexts
    let encryption_ciphertext = Ciphertext::from_words(
        &tx.actions[0].logic_verifier_inputs[1]
            .app_data
            .resource_payload[0]
            .blob,
    );
    let decrypted_resource = encryption_ciphertext
        .decrypt(&created_encryption_sk)
        .unwrap();
    assert_eq!(decrypted_resource, created_resource.to_bytes().unwrap());

    // Verify the transaction
    tx.verify().unwrap();
}
