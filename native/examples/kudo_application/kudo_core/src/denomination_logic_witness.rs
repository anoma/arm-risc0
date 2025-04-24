use aarm_core::{
    action_tree::ACTION_TREE_DEPTH,
    authorization::{AuthorizationSignature, AuthorizationVerifyingKey},
    encryption::Ciphertext,
    logic_instance::LogicInstance,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
};
use risc0_zkvm::sha::{Impl, Sha256};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct DenominationLogicWitness {
    // Denomination related fields
    pub denomination_resource: Resource,
    pub denomination_existence_path: MerklePath<ACTION_TREE_DEPTH>,
    // There are three types of signatures: issuance, burn, and consumption.
    // Only one is enabled at a time.
    pub signature: AuthorizationSignature,

    // Kudo related fields
    pub kudo_resource: Resource,
    pub kudo_existence_path: MerklePath<ACTION_TREE_DEPTH>,
    pub kudo_is_consumed: bool,
    pub kudo_nf_key: NullifierKey,
    pub kudo_issuer: AuthorizationVerifyingKey,
    pub kudo_owner: AuthorizationVerifyingKey,
}

impl DenominationLogicWitness {
    pub fn constrain(&self) -> LogicInstance {
        // Load self resource, the denomination resource is always a created
        // resource
        let tag = self.denomination_resource.commitment();
        let root = self.denomination_existence_path.root(tag);

        // Check basic properties of the denomination resource
        assert_eq!(self.denomination_resource.quantity, 0);
        assert!(self.denomination_resource.is_ephemeral);

        // Load the kudo resource
        let kudo_cm = self.kudo_resource.commitment();
        let kudo_tag = if self.kudo_is_consumed {
            self.kudo_resource
                .nullifier_from_commitment(&self.kudo_nf_key, &kudo_cm)
                .unwrap()
        } else {
            kudo_cm
        };
        let kudo_root = self.kudo_existence_path.root(kudo_tag);
        assert_eq!(root, kudo_root);

        // Decode label of the kudo resource and check the correspondence between the
        // kudo resource and the domination resource
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.denomination_resource.logic_ref.as_bytes());
        bytes.extend_from_slice(&self.kudo_issuer.to_bytes());
        assert_eq!(self.kudo_resource.label_ref, *Impl::hash_bytes(&bytes));

        if self.kudo_resource.is_ephemeral {
            // Constrain the ephemeral kudo resource(Issurance and Burn)

            // Both insurance and burn should verify the issuer's signature. It
            // implies that only the issuer can burn resouces in this example.
            // It makes more sense to let the owner burn resources in practice?
            assert!(self
                .kudo_issuer
                .verify(root.as_bytes(), &self.signature)
                .is_ok());

            // The issuer must be the owner when burning the resource.
            if !self.kudo_is_consumed {
                assert_eq!(self.kudo_owner, self.kudo_issuer);
            }
        } else {
            // Constrain persistent kudo resource consumption
            // Verify the owner's signature
            assert!(self
                .kudo_owner
                .verify(root.as_bytes(), &self.signature,)
                .is_ok());
        }

        LogicInstance {
            tag,
            is_consumed: false, // denomination resources are always created
            root,
            cipher: Ciphertext::default(), // no cipher needed
            app_data: Vec::new(),          // no app data needed
        }
    }
}
