use aarm_core::{
    action_tree::ACTION_TREE_DEPTH,
    authorization::{AuthorizationSignature, AuthorizationVerifyingKey},
    encryption::{Ciphertext, SecretKey},
    logic_instance::LogicInstance,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
};
use risc0_zkvm::sha::{Impl, Sha256};
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

impl KudoLogicWitness {
    pub fn constrain(&self) -> LogicInstance {
        // Load the kudo resource
        let self_cm = self.kudo_resource.commitment();
        let tag = if self.is_consumed {
            self.kudo_resource
                .nullifier_from_commitment(&self.nf_key, &self_cm)
                .unwrap()
        } else {
            self_cm
        };
        let root = self.kudo_existence_path.root(tag);

        // Load the denomination resource
        let dr_cm = self.denomination_resource.commitment();
        let dr_root = self.denomination_existence_path.root(dr_cm);
        assert_eq!(root, dr_root);

        // Decode label of the kudo resource and check the correspondence between the
        // kudo resource and the domination resource
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.denomination_resource.logic_ref.as_bytes());
        bytes.extend_from_slice(&self.issuer.to_bytes());
        assert_eq!(self.kudo_resource.label_ref, *Impl::hash_bytes(&bytes));

        // Constrain the receive logic if creating a persistent resource
        if !self.is_consumed && !self.kudo_resource.is_ephemeral {
            // Load the receive resource
            let rr_cm = self.receive_resource.commitment();
            let rr_root = self.receive_existence_path.root(rr_cm);
            assert_eq!(root, rr_root);

            // Check value = identity
            let owner_bytes = self.owner.to_bytes();
            assert_eq!(
                self.kudo_resource.value_ref,
                *Impl::hash_bytes(&owner_bytes)
            );

            // Check receive_resource.label = kudo_resource.cm
            assert_eq!(self.receive_resource.label_ref, self_cm);

            // Verify signature
            let mut receive_logic_and_owner_bytes = Vec::new();
            receive_logic_and_owner_bytes
                .extend_from_slice(self.receive_resource.logic_ref.as_bytes());
            receive_logic_and_owner_bytes.extend_from_slice(&owner_bytes);
            assert!(self
                .owner
                .verify(&receive_logic_and_owner_bytes, &self.receiver_signature)
                .is_ok());
        }

        // Generate the ciphertext
        let cipher = self.generate_ciphertext();

        LogicInstance {
            tag,
            is_consumed: self.is_consumed,
            root,
            cipher,
            app_data: Vec::new(),
        }
    }

    fn generate_ciphertext(&self) -> Ciphertext {
        if self.kudo_resource.is_ephemeral || self.is_consumed {
            Ciphertext::default()
        } else {
            Ciphertext::encrypt(
                &self.kudo_resource.to_bytes(),
                self.owner.as_affine(),
                &self.encryption_sk,
                self.encryption_nonce,
            )
        }
    }
}
