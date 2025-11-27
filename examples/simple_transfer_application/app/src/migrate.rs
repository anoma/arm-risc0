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
    Digest,
};

use crate::TransferLogic;

#[allow(clippy::too_many_arguments)]
pub fn construct_migrate_tx(
    // Parameters for the consumed resource
    consumed_resource: Resource,
    latest_cm_tree_root: Digest,
    consumed_nf_key: NullifierKey,
    forwarder_addr: Vec<u8>,
    token_addr: Vec<u8>,
    user_addr: Vec<u8>,

    // Parameters for migrated resource via forwarder
    migrated_resource: Resource,
    migrated_nf_key: NullifierKey,
    migrated_resource_path: MerklePath,
    migrated_auth_pk: AuthorizationVerifyingKey,
    migrated_auth_sig: AuthorizationSignature,

    // Parameters for the created resource
    created_resource: Resource,
    created_discovery_pk: AffinePoint,
    created_encryption_pk: AffinePoint,
) -> Result<Transaction, ArmError> {
    // Action tree
    let consumed_nf = consumed_resource.nullifier(&consumed_nf_key)?;
    let created_cm = created_resource.commitment();
    let action_tree_root = MerkleTree::new(vec![consumed_nf, created_cm]).root();

    // Generate compliance units
    let compliance_witness = ComplianceWitness::from_resources(
        consumed_resource,
        latest_cm_tree_root,
        consumed_nf_key.clone(),
        created_resource,
    );
    let compliance_unit = ComplianceUnit::create(&compliance_witness)?;

    // Generate logic proofs
    let consumed_resource_logic = TransferLogic::migrate_resource_logic(
        consumed_resource,
        action_tree_root,
        consumed_nf_key,
        forwarder_addr.clone(),
        token_addr.clone(),
        user_addr.clone(),
        migrated_resource,
        migrated_nf_key,
        migrated_resource_path,
        migrated_auth_pk,
        migrated_auth_sig,
    );
    let consumed_logic_proof = consumed_resource_logic.prove()?;

    let created_resource_logic = TransferLogic::create_persistent_resource_logic(
        created_resource,
        action_tree_root,
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
fn simple_migrate_test() {
    use crate::resource::{construct_ephemeral_resource, construct_persistent_resource};
    use crate::utils::authorize_the_action;
    use arm::{
        authorization::{AuthorizationSigningKey, AuthorizationVerifyingKey},
        compliance::INITIAL_ROOT,
        encryption::random_keypair,
        nullifier_key::NullifierKey,
    };
    use simple_transfer_witness::{
        calculate_label_ref, calculate_value_ref_from_auth, FORWARDER_ADDRESS_V1, LOGIC_V1,
    };

    // Common parameters
    let forwarder_addr_v2 = vec![1u8; 20];
    let token_addr = vec![2u8; 20];
    let user_addr = vec![3u8; 20];
    let quantity = 100;
    let label_ref = calculate_label_ref(FORWARDER_ADDRESS_V1.as_bytes(), &token_addr);

    // Construct the migrated resource
    let migrated_resource_sk = AuthorizationSigningKey::from_bytes(&[9u8; 32]).unwrap();
    let migrated_resource_pk = AuthorizationVerifyingKey::from_signing_key(&migrated_resource_sk);
    let migrated_value_ref = calculate_value_ref_from_auth(&migrated_resource_pk);
    let migrated_nf_key = NullifierKey::default();
    let migrated_nf_cm = migrated_nf_key.commit();
    let migrated_resource = Resource {
        logic_ref: *LOGIC_V1,
        nk_commitment: migrated_nf_cm,
        label_ref,
        value_ref: migrated_value_ref,
        quantity,
        is_ephemeral: false,
        ..Default::default()
    };

    let migrated_cm = migrated_resource.commitment();
    println!("Migrated resource cm: {:?}", migrated_cm);

    // Construct the consumed resource
    let (consumed_nf_key, consumed_nf_cm) = NullifierKey::random_pair();
    let consumed_resource = construct_ephemeral_resource(
        &forwarder_addr_v2,
        &token_addr,
        quantity,
        [4u8; 32], // nonce
        consumed_nf_cm,
        [5u8; 32], // rand_seed
        &user_addr,
    );
    let consumed_nf = consumed_resource.nullifier(&consumed_nf_key).unwrap();
    // Fetch the latest cm tree root from the chain
    let latest_cm_tree_root = *INITIAL_ROOT;

    // Generate the created resource
    let (_created_nf_key, created_nf_cm) = NullifierKey::random_pair();
    let created_auth_sk = AuthorizationSigningKey::new();
    let created_auth_pk = AuthorizationVerifyingKey::from_signing_key(&created_auth_sk);
    let (_created_discovery_sk, created_discovery_pk) = random_keypair();
    let (_created_encryption_sk, created_encryption_pk) = random_keypair();
    let created_resource = construct_persistent_resource(
        &forwarder_addr_v2,
        &token_addr,
        quantity,
        consumed_nf.as_bytes().try_into().unwrap(), // nonce
        created_nf_cm,
        [6u8; 32], // rand_seed
        &created_auth_pk,
    );
    let created_cm = created_resource.commitment();

    // Generate the authorization signature
    let action_tree = MerkleTree::new(vec![consumed_nf, created_cm]);
    let migrated_auth_sig = authorize_the_action(&migrated_resource_sk, &action_tree);

    // Construct the migration transaction
    let tx_start_timer = std::time::Instant::now();
    let tx = construct_migrate_tx(
        consumed_resource,
        latest_cm_tree_root,
        consumed_nf_key,
        forwarder_addr_v2,
        token_addr,
        user_addr,
        migrated_resource,
        migrated_nf_key,
        MerklePath::from_path(&[]), // dummy path
        migrated_resource_pk,
        migrated_auth_sig,
        created_resource,
        created_discovery_pk,
        created_encryption_pk,
    )
    .unwrap();
    println!("Tx build duration time: {:?}", tx_start_timer.elapsed());

    // Verify the transaction
    tx.verify().unwrap();
}
