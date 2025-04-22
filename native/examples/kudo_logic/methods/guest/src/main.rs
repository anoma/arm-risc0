use aarm_core::{
    action_tree::ACTION_TREE_DEPTH,
    authorization::{AuthorizationSignature, AuthorizationVerifyingKey},
    encryption::{Ciphertext, SecretKey},
    logic_instance::LogicInstance,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
};
use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct KudoLogicWitness {
    // Kudo related fields
    pub kudo_resource: Resource,
    pub kudo_existence_path: MerklePath<ACTION_TREE_DEPTH>,
    pub is_consumed: bool,
    pub nf_key: NullifierKey,
    pub issuer: AuthorizationVerifyingKey,
    pub encryption_sk: SecretKey,
    pub encryption_nonce: [u8; 12],

    // Denomination related fields
    pub denomination_resource: Resource,
    pub denomination_existence_path: MerklePath<ACTION_TREE_DEPTH>,

    // Receive related fields
    pub receive_resource: Resource,
    pub owner: AuthorizationVerifyingKey,
    pub receiver_signature: AuthorizationSignature,
    pub receive_existence_path: MerklePath<ACTION_TREE_DEPTH>,
}

fn main() {
    // read the input
    let witness: KudoLogicWitness = env::read();

    // Load the kudo resource
    let self_cm = witness.kudo_resource.commitment();
    let tag = if witness.is_consumed {
        witness
            .kudo_resource
            .nullifier_from_commitment(&witness.nf_key, &self_cm)
            .unwrap()
    } else {
        self_cm
    };
    let root = witness.kudo_existence_path.root(tag);

    // Load the denomination resource
    let dr_cm = witness.denomination_resource.commitment();
    let dr_root = witness.denomination_existence_path.root(dr_cm);
    assert_eq!(root, dr_root);

    // Decode label of the kudo resource and check the correspondence between the
    // kudo resource and the domination resource
    let mut bytes = Vec::new();
    bytes.extend_from_slice(witness.denomination_resource.logic_ref.as_bytes());
    bytes.extend_from_slice(&witness.issuer.to_bytes());
    assert_eq!(witness.kudo_resource.label_ref, *Impl::hash_bytes(&bytes));

    // Constrain the receive logic and generate the cipher if creating a
    // persistent resource
    let cipher = if !witness.is_consumed && !witness.kudo_resource.is_ephemeral {
        // Load the receive resource
        let rr_cm = witness.receive_resource.commitment();
        let rr_root = witness.receive_existence_path.root(rr_cm);
        assert_eq!(root, rr_root);

        // Check value = identity
        let owner_bytes = witness.owner.to_bytes();
        assert_eq!(
            witness.kudo_resource.value_ref,
            *Impl::hash_bytes(&owner_bytes)
        );

        // Check receive_resource.label = kudo_resource.cm
        assert_eq!(witness.receive_resource.label_ref, self_cm);

        // Verify signature
        let mut receive_logic_and_owner_bytes = Vec::new();
        receive_logic_and_owner_bytes
            .extend_from_slice(witness.receive_resource.logic_ref.as_bytes());
        receive_logic_and_owner_bytes.extend_from_slice(&owner_bytes);
        assert!(witness
            .owner
            .verify(&receive_logic_and_owner_bytes, &witness.receiver_signature)
            .is_ok());

        // Generate the ciphertext
        let plain_text = witness.kudo_resource.to_bytes();
        Ciphertext::encrypt(
            &plain_text,
            witness.owner.as_affine(),
            &witness.encryption_sk,
            witness.encryption_nonce,
        )
    } else {
        // If consumed, the ciphertext is empty
        Ciphertext::default()
    };

    let instance = LogicInstance {
        tag,
        is_consumed: witness.is_consumed,
        root,
        cipher,
        app_data: Vec::new(),
    };

    // write public output to the journal
    env::commit(&instance);
}
