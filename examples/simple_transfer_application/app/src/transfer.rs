#[test]
fn simple_transfer_test() {
    use crate::{calculate_value_ref, TransferLogic};
    use arm::{
        action::Action,
        action_tree::MerkleTree,
        authorization::{AuthorizationSigningKey, AuthorizationVerifyingKey},
        compliance::ComplianceWitness,
        compliance_unit::ComplianceUnit,
        delta_proof::DeltaWitness,
        encryption::{random_keypair, Ciphertext},
        logic_proof::LogicProver,
        merkle_path::MerklePath,
        nullifier_key::NullifierKey,
        resource::Resource,
        transaction::{Delta, Transaction},
        utils::words_to_bytes,
    };

    let logic_ref = TransferLogic::verifying_key_as_bytes();
    let quantity = 100;
    // Obtain the consumed resource data
    let consumed_auth_sk = AuthorizationSigningKey::new();
    let consumed_auth_pk = AuthorizationVerifyingKey::from_signing_key(&consumed_auth_sk);
    let (consumed_nf_key, consumed_nf_cm) = NullifierKey::random_pair();
    let (consumed_discovery_sk, consumed_discovery_pk) = random_keypair();
    let (consumed_encryption_sk, consumed_encryption_pk) = random_keypair();
    let consumed_resource = Resource {
        logic_ref: logic_ref.clone(),
        label_ref: vec![0; 32],
        quantity,
        value_ref: calculate_value_ref(&consumed_auth_pk),
        is_ephemeral: false,
        nonce: vec![0; 32],
        nk_commitment: consumed_nf_cm,
        rand_seed: vec![0; 32],
    };
    let consumed_nf = consumed_resource.nullifier(&consumed_nf_key).unwrap();

    // Create the created resource data
    let (_created_nf_key, created_nf_cm) = NullifierKey::random_pair();
    let (_created_discovery_sk, created_discovery_pk) = random_keypair();
    let (_created_encryption_sk, created_encryption_pk) = random_keypair();
    let created_resource = Resource {
        logic_ref,
        label_ref: vec![0; 32],
        quantity,
        value_ref: vec![0; 32], // a trivial receiver_pk
        is_ephemeral: false,
        nonce: consumed_nf.as_bytes().to_vec(),
        nk_commitment: created_nf_cm,
        rand_seed: vec![1; 32],
    };
    let created_cm = created_resource.commitment();

    // Get the authorization signature, it can be from external signing(e.g. wallet)
    let action_tree = MerkleTree::new(vec![consumed_nf, created_cm]);
    let action_tree_root = action_tree.root();
    let auth_sig = consumed_auth_sk.sign(words_to_bytes(&action_tree_root));

    // Generate compliance units
    let merkle_path = MerklePath::default(); // mock a path
    let compliance_witness = ComplianceWitness::from_resources_with_path(
        consumed_resource.clone(),
        consumed_nf_key.clone(),
        merkle_path,
        created_resource.clone(),
    );
    let compliance_unit = ComplianceUnit::create(&compliance_witness);

    // Generate logic proofs
    let consumed_resource_path = action_tree.generate_path(&consumed_nf).unwrap();
    let consumed_resource_logic = TransferLogic::consume_persistent_resource_logic(
        consumed_resource.clone(),
        consumed_resource_path,
        consumed_nf_key,
        consumed_auth_pk,
        auth_sig,
        consumed_discovery_pk,
        consumed_encryption_pk,
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

    // check the discovery ciphertexts
    let discovery_ciphertext = Ciphertext::from_words(
        &tx.actions[0].logic_verifier_inputs[0]
            .app_data
            .discovery_payload[0]
            .blob,
    );
    discovery_ciphertext
        .decrypt(&consumed_discovery_sk)
        .unwrap();

    // check the encryption ciphertexts
    let encryption_ciphertext = Ciphertext::from_words(
        &tx.actions[0].logic_verifier_inputs[0]
            .app_data
            .resource_payload[0]
            .blob,
    );
    let decrypted_resource = encryption_ciphertext
        .decrypt(&consumed_encryption_sk)
        .unwrap();
    assert_eq!(decrypted_resource, consumed_resource.to_bytes());

    // Verify the transaction
    assert!(tx.verify(), "Transaction verification failed");
}
