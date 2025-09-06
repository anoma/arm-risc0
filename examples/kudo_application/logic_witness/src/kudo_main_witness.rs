use crate::utils::compute_kudo_label;
pub use arm::resource_logic::LogicCircuit;
use arm::{
    authorization::{AuthorizationSignature, AuthorizationVerifyingKey},
    encryption::{Ciphertext, SecretKey},
    logic_instance::{AppData, ExpirableBlob, LogicInstance},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
};
use rand::Rng;
use risc0_zkvm::sha::{Impl, Sha256};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct KudoMainWitness {
    // Kudo related fields
    pub kudo_resource: Resource,
    pub kudo_existence_path: MerklePath,
    pub kudo_is_consumed: bool,
    pub kudo_nf_key: NullifierKey,
    pub issuer: AuthorizationVerifyingKey,
    pub encryption_sk: SecretKey,
    pub encryption_nonce: [u8; 12],

    // Denomination related fields
    pub denomination_resource: Resource,
    pub denomination_existence_path: MerklePath,
    pub denomination_is_consumed: bool,
    pub denomination_nf_key: NullifierKey,

    // Receive related fields
    pub receive_resource: Resource,
    pub receive_nf_key: NullifierKey,
    pub receive_is_consumed: bool,
    pub owner: AuthorizationVerifyingKey,
    pub receiver_signature: AuthorizationSignature,
    pub receive_existence_path: MerklePath,
}

impl LogicCircuit for KudoMainWitness {
    fn constrain(&self) -> LogicInstance {
        // Load the kudo resource
        let tag = self
            .kudo_resource
            .tag(self.kudo_is_consumed, &self.kudo_nf_key);
        let root = self.kudo_existence_path.root(&tag);

        // Load the denomination resource
        let dr_cm = self.denomination_resource.commitment();
        let dr_tag = if self.denomination_is_consumed {
            self.denomination_resource
                .nullifier_from_commitment(&self.denomination_nf_key, &dr_cm)
                .unwrap()
        } else {
            dr_cm
        };
        let dr_root = self.denomination_existence_path.root(&dr_tag);
        assert_eq!(root, dr_root);

        // Check denomination.label = kudo_resource.tag
        let tag_bytes = tag.as_bytes().to_vec();
        assert_eq!(self.denomination_resource.label_ref, tag_bytes);

        // Decode label of the kudo resource and check the correspondence between the
        // kudo resource and the domination resource
        let label = compute_kudo_label(&self.kudo_resource.logic_ref, &self.issuer);
        assert_eq!(self.kudo_resource.label_ref, label);

        // Constrain the receive logic if creating a persistent resource
        if !self.kudo_is_consumed && !self.kudo_resource.is_ephemeral {
            // Load the receive resource
            let rr_cm = self.receive_resource.commitment();
            let rr_tag = if self.receive_is_consumed {
                self.receive_resource
                    .nullifier_from_commitment(&self.receive_nf_key, &rr_cm)
                    .unwrap()
            } else {
                rr_cm
            };
            let rr_root = self.receive_existence_path.root(&rr_tag);
            assert_eq!(root, rr_root);

            // Check value = identity
            let owner_bytes = self.owner.to_bytes();
            assert_eq!(
                self.kudo_resource.value_ref,
                *Impl::hash_bytes(&owner_bytes).as_bytes().to_vec()
            );

            // Check receive_resource.label = kudo_resource.tag
            assert_eq!(self.receive_resource.label_ref, tag_bytes);

            // Verify signature
            let mut receive_logic_and_owner_bytes = self.receive_resource.logic_ref.clone();
            receive_logic_and_owner_bytes.extend_from_slice(&owner_bytes);
            assert!(self
                .owner
                .verify(&receive_logic_and_owner_bytes, &self.receiver_signature)
                .is_ok());
        }

        // Generate the ciphertext
        let cipher = self.generate_ciphertext().as_words();
        let cipher_expirable_blob = ExpirableBlob {
            blob: cipher,
            deletion_criterion: 1,
        };
        let app_data = AppData {
            resource_payload: vec![cipher_expirable_blob],
            discovery_payload: Vec::new(),
            external_payload: Vec::new(),
            application_payload: Vec::new(),
        };

        LogicInstance {
            tag: tag.as_words().to_vec(),
            is_consumed: self.kudo_is_consumed,
            root,
            app_data,
        }
    }
}

impl KudoMainWitness {
    fn generate_ciphertext(&self) -> Ciphertext {
        if self.kudo_resource.is_ephemeral || self.kudo_is_consumed {
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

    #[allow(clippy::too_many_arguments)]
    pub fn generate_persistent_resource_creation_witness(
        kudo_resource: Resource,
        kudo_existence_path: MerklePath,
        issuer: AuthorizationVerifyingKey,
        denomination_resource: Resource,
        denomination_existence_path: MerklePath,
        denomination_nf_key: NullifierKey,
        denomination_is_consumed: bool,
        receive_resource: Resource,
        receive_nf_key: NullifierKey,
        receive_is_consumed: bool,
        receive_existence_path: MerklePath,
        owner: AuthorizationVerifyingKey,
        receiver_signature: AuthorizationSignature,
    ) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            kudo_resource,
            kudo_existence_path,
            kudo_is_consumed: false,
            kudo_nf_key: NullifierKey::default(), // not used
            issuer,
            encryption_sk: SecretKey::random(),
            encryption_nonce: rng.gen(),
            denomination_resource,
            denomination_existence_path,
            denomination_is_consumed,
            denomination_nf_key,
            receive_resource,
            receive_nf_key,
            receive_is_consumed,
            owner,
            receiver_signature,
            receive_existence_path,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn generate_persistent_resource_consumption_witness(
        kudo_resource: Resource,
        kudo_existence_path: MerklePath,
        kudo_nf_key: NullifierKey,
        issuer: AuthorizationVerifyingKey,
        denomination_resource: Resource,
        denomination_existence_path: MerklePath,
        denomination_is_consumed: bool,
        denomination_nf_key: NullifierKey,
    ) -> Self {
        Self {
            kudo_resource,
            kudo_existence_path,
            kudo_is_consumed: true,
            kudo_nf_key,
            issuer,
            encryption_sk: SecretKey::default(), // not used
            encryption_nonce: [0u8; 12],         // not used
            denomination_resource,
            denomination_existence_path,
            denomination_is_consumed,
            denomination_nf_key,
            receive_resource: Resource::default(),   // not used
            receive_nf_key: NullifierKey::default(), // not used
            receive_is_consumed: false,              // not used
            owner: AuthorizationVerifyingKey::default(), // not used
            receiver_signature: AuthorizationSignature::default(), // not used
            receive_existence_path: MerklePath::default(), // not used
        }
    }

    pub fn generate_consumed_ephemeral_witness(
        kudo_resource: Resource,
        kudo_existence_path: MerklePath,
        kudo_nf_key: NullifierKey,
        issuer: AuthorizationVerifyingKey,
        denomination_resource: Resource,
        denomination_existence_path: MerklePath,
    ) -> Self {
        Self {
            kudo_resource,
            kudo_existence_path,
            kudo_is_consumed: true,
            kudo_nf_key,
            issuer,
            encryption_sk: SecretKey::default(),
            encryption_nonce: [0u8; 12],
            denomination_resource,
            denomination_existence_path,
            denomination_is_consumed: false,
            denomination_nf_key: NullifierKey::default(), // not used
            receive_resource: Resource::default(),        // not used
            receive_nf_key: NullifierKey::default(),      // not used
            receive_is_consumed: false,                   // not used
            owner: AuthorizationVerifyingKey::default(),  // not used
            receiver_signature: AuthorizationSignature::default(), // not used
            receive_existence_path: MerklePath::default(), // not used
        }
    }

    pub fn generate_created_ephemeral_witness(
        kudo_resource: Resource,
        kudo_existence_path: MerklePath,
        issuer: AuthorizationVerifyingKey,
        denomination_resource: Resource,
        denomination_existence_path: MerklePath,
        denomination_nf_key: NullifierKey,
    ) -> Self {
        Self {
            kudo_resource,
            kudo_existence_path,
            kudo_is_consumed: false,
            kudo_nf_key: NullifierKey::default(), // not used
            issuer,
            encryption_sk: SecretKey::default(),
            encryption_nonce: [0u8; 12],
            denomination_resource,
            denomination_existence_path,
            denomination_is_consumed: true,
            denomination_nf_key,
            receive_resource: Resource::default(),   // not used
            receive_nf_key: NullifierKey::default(), // not used
            receive_is_consumed: false,              // not used
            owner: AuthorizationVerifyingKey::default(), // not used
            receiver_signature: AuthorizationSignature::default(), // not used
            receive_existence_path: MerklePath::default(), // not used
        }
    }
}
