use crate::utils::compute_kudo_label;
pub use arm::resource_logic::LogicCircuit;
use arm::{
    action_tree::ACTION_TREE_DEPTH,
    authorization::{AuthorizationSignature, AuthorizationVerifyingKey},
    logic_instance::{AppData, LogicInstance},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    utils::words_to_bytes,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SimpleDenominationLogicWitness {
    // Denomination related fields
    pub denomination_resource: Resource,
    pub denomination_is_consumed: bool, // It can be either consumed or created
    pub denomination_nf_key: NullifierKey,
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

impl LogicCircuit for SimpleDenominationLogicWitness {
    fn constrain(&self) -> LogicInstance {
        // Load self resource, the denomination resource is always a created
        // resource
        let denomination_cm = self.denomination_resource.commitment();
        let denomination_tag = if self.denomination_is_consumed {
            self.denomination_resource
                .nullifier_from_commitment(&self.denomination_nf_key, &denomination_cm)
                .unwrap()
        } else {
            denomination_cm
        };
        let root = self.denomination_existence_path.root(&denomination_tag);

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
        let kudo_root = self.kudo_existence_path.root(&kudo_tag);
        assert_eq!(root, kudo_root);
        let root_bytes = words_to_bytes(&root);

        // Check denomination.label = kudo_resource.tag
        assert_eq!(self.denomination_resource.label_ref, kudo_tag.as_bytes());

        // Decode label of the kudo resource and check the correspondence between the
        // kudo resource and the domination resource
        let label = compute_kudo_label(&self.kudo_resource.logic_ref, &self.kudo_issuer);
        assert_eq!(self.kudo_resource.label_ref, label);

        if self.kudo_resource.is_ephemeral {
            // Constrain the ephemeral kudo resource(Issurance and Burn)

            // Both insurance and burn should verify the issuer's signature. It
            // implies that only the issuer can burn resouces in this example.
            // It makes more sense to let the owner burn resources in practice?
            assert!(self.kudo_issuer.verify(root_bytes, &self.signature).is_ok());

            // The issuer must be the owner when burning the resource.
            if !self.kudo_is_consumed {
                assert_eq!(self.kudo_owner, self.kudo_issuer);
            }
        } else if self.kudo_is_consumed {
            // Constrain persistent kudo resource consumption
            // Verify the owner's signature
            assert!(self.kudo_owner.verify(root_bytes, &self.signature).is_ok());
        }

        LogicInstance {
            tag: denomination_tag.as_words().to_vec(),
            is_consumed: self.denomination_is_consumed,
            root,
            app_data: AppData::default(), // no app data needed
        }
    }
}

impl SimpleDenominationLogicWitness {
    // Seems this logic does nothing in this case
    // Create a denomination witness corresponding to a created kudo resource
    pub fn generate_created_kudo_denomination_witness(
        denomination_resource: Resource,
        denomination_existence_path: MerklePath<ACTION_TREE_DEPTH>,
        denomination_is_consumed: bool,
        denomination_nf_key: NullifierKey,
        kudo_resource: Resource,
        kudo_existence_path: MerklePath<ACTION_TREE_DEPTH>,
        kudo_issuer: AuthorizationVerifyingKey,
    ) -> Self {
        Self {
            denomination_resource,
            denomination_is_consumed,
            denomination_nf_key,
            denomination_existence_path,
            signature: AuthorizationSignature::default(), // not used
            kudo_resource,
            kudo_existence_path,
            kudo_is_consumed: false,
            kudo_nf_key: NullifierKey::default(), // not used
            kudo_issuer,
            kudo_owner: AuthorizationVerifyingKey::default(), // not used
        }
    }

    // Create a witness for the issuance of an ephemeral kudo resource
    pub fn generate_issued_ephemeral_witness(
        denomination_resource: Resource,
        denomination_existence_path: MerklePath<ACTION_TREE_DEPTH>,
        signature: AuthorizationSignature,
        kudo_resource: Resource,
        kudo_existence_path: MerklePath<ACTION_TREE_DEPTH>,
        kudo_nf_key: NullifierKey,
        kudo_issuer: AuthorizationVerifyingKey,
    ) -> Self {
        Self {
            denomination_resource,
            denomination_is_consumed: false,
            denomination_nf_key: NullifierKey::default(), // not used
            denomination_existence_path,
            signature,
            kudo_resource,
            kudo_existence_path,
            kudo_is_consumed: true,
            kudo_nf_key,
            kudo_issuer,
            kudo_owner: AuthorizationVerifyingKey::default(), // not used
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn generate_denomimation_witness(
        denomination_resource: Resource,
        denomination_existence_path: MerklePath<ACTION_TREE_DEPTH>,
        denomination_is_consumed: bool,
        denomination_nf_key: NullifierKey,
        signature: AuthorizationSignature,
        kudo_resource: Resource,
        kudo_existence_path: MerklePath<ACTION_TREE_DEPTH>,
        kudo_is_consumed: bool,
        kudo_nf_key: NullifierKey,
        kudo_issuer: AuthorizationVerifyingKey,
        kudo_owner: AuthorizationVerifyingKey,
    ) -> Self {
        Self {
            denomination_resource,
            denomination_is_consumed,
            denomination_nf_key,
            denomination_existence_path,
            signature,
            kudo_resource,
            kudo_existence_path,
            kudo_is_consumed,
            kudo_nf_key,
            kudo_issuer,
            kudo_owner,
        }
    }

    // Create a witness for the burn, corresponding to an ephemeral kudo resource
    #[allow(clippy::too_many_arguments)]
    pub fn generate_burned_ephemeral_witness(
        denomination_resource: Resource,
        denomination_existence_path: MerklePath<ACTION_TREE_DEPTH>,
        denomination_nf_key: NullifierKey,
        signature: AuthorizationSignature,
        kudo_resource: Resource,
        kudo_existence_path: MerklePath<ACTION_TREE_DEPTH>,
        kudo_issuer: AuthorizationVerifyingKey,
        kudo_owner: AuthorizationVerifyingKey,
    ) -> Self {
        Self {
            denomination_resource,
            denomination_is_consumed: true,
            denomination_nf_key, // not used
            denomination_existence_path,
            signature,
            kudo_resource,
            kudo_existence_path,
            kudo_is_consumed: false,
            kudo_nf_key: NullifierKey::default(), // not used
            kudo_issuer,
            kudo_owner,
        }
    }
}
