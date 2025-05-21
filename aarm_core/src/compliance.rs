use crate::{
    constants::{INITIAL_ROOT, TRIVIAL_RESOURCE_LOGIC_VK},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
};
use k256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field,
    },
    EncodedPoint, ProjectivePoint, Scalar,
};
use risc0_zkvm::sha::{Digest, Impl, Sha256};

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ComplianceInstance {
    pub consumed_nullifier: Digest,
    pub consumed_logic_ref: Digest,
    pub created_commitment: Digest,
    pub created_logic_ref: Digest,
    pub merkle_root: Digest,
    pub delta_x: [u8; 32],
    pub delta_y: [u8; 32],
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceWitness<const COMMITMENT_TREE_DEPTH: usize> {
    /// The consumed resource
    pub consumed_resource: Resource,
    /// The path from the consumed commitment to the root in the commitment tree
    pub merkle_path: MerklePath<COMMITMENT_TREE_DEPTH>,
    /// The existing root for the ephemeral resource
    pub ephemeral_root: Digest,
    /// Nullifier key of the consumed resource
    pub nf_key: NullifierKey,
    /// The created resource
    pub created_resource: Resource,
    /// Random scalar for delta commitment
    pub rcv: Scalar,
    // TODO: If we want to add function privacy, include:
    // pub input_resource_logic_cm_r: [u8; DATA_BYTES],
    // pub output_resource_logic_cm_r: [u8; DATA_BYTES],
}

impl<const COMMITMENT_TREE_DEPTH: usize> ComplianceWitness<COMMITMENT_TREE_DEPTH> {
    pub fn from_resources(
        consumed_resource: Resource,
        nf_key: NullifierKey,
        created_resource: Resource,
    ) -> Self {
        let rng = rand::thread_rng();
        ComplianceWitness {
            consumed_resource,
            created_resource,
            merkle_path: MerklePath::<COMMITMENT_TREE_DEPTH>::default(),
            rcv: Scalar::random(rng),
            nf_key,
            ephemeral_root: *INITIAL_ROOT,
        }
    }

    pub fn from_resources_with_path(
        consumed_resource: Resource,
        nf_key: NullifierKey,
        merkle_path: MerklePath<COMMITMENT_TREE_DEPTH>,
        created_resource: Resource,
    ) -> Self {
        let rng = rand::thread_rng();
        let rcv = Scalar::random(rng);
        ComplianceWitness {
            consumed_resource,
            created_resource,
            merkle_path,
            rcv,
            nf_key,
            ephemeral_root: Digest::default(), // not used
        }
    }

    // Only for tests
    pub fn with_fixed_rcv(
        consumed_resource: Resource,
        nf_key: NullifierKey,
        created_resource: Resource,
    ) -> Self {
        ComplianceWitness {
            consumed_resource,
            created_resource,
            merkle_path: MerklePath::<COMMITMENT_TREE_DEPTH>::default(),
            rcv: Scalar::ONE,
            nf_key,
            ephemeral_root: *INITIAL_ROOT,
        }
    }

    pub fn constrain(&self) -> ComplianceInstance {
        let consumed_logic_ref = self.get_consumed_resource_logic();
        let comsumed_cm = self.consumed_commitment();
        let consumed_nullifier = self.consumed_nullifier(&comsumed_cm);
        let created_logic_ref = self.get_created_resource_logic();
        let created_commitment = self.created_commitment();
        let merkle_root = self.merkle_tree_root(comsumed_cm);
        let (delta_x, delta_y) = self.delta_commitment();

        ComplianceInstance {
            consumed_nullifier,
            created_commitment,
            consumed_logic_ref,
            created_logic_ref,
            merkle_root,
            delta_x,
            delta_y,
        }
    }

    pub fn get_consumed_resource_logic(&self) -> Digest {
        self.consumed_resource.logic_ref
    }

    pub fn get_created_resource_logic(&self) -> Digest {
        self.created_resource.logic_ref
    }

    pub fn consumed_commitment(&self) -> Digest {
        self.consumed_resource.commitment()
    }

    pub fn created_commitment(&self) -> Digest {
        self.created_resource.commitment()
    }

    pub fn consumed_nullifier(&self, cm: &Digest) -> Digest {
        self.consumed_resource
            .nullifier_from_commitment(&self.nf_key, cm)
            .unwrap()
    }

    pub fn merkle_tree_root(&self, cm: Digest) -> Digest {
        if self.consumed_resource.is_ephemeral {
            self.ephemeral_root
        } else {
            self.merkle_path.root(cm)
        }
    }

    pub fn delta_commitment(&self) -> ([u8; 32], [u8; 32]) {
        // Compute delta and make delta commitment public
        let delta = self.consumed_resource.kind() * self.consumed_resource.quantity_scalar()
            - self.created_resource.kind() * self.created_resource.quantity_scalar()
            + ProjectivePoint::GENERATOR * self.rcv;

        let encoded_delta = delta.to_encoded_point(false);
        (
            encoded_delta.x().unwrap().as_slice().try_into().unwrap(),
            encoded_delta.y().unwrap().as_slice().try_into().unwrap(),
        )
    }
}

impl<const COMMITMENT_TREE_DEPTH: usize> Default for ComplianceWitness<COMMITMENT_TREE_DEPTH> {
    fn default() -> Self {
        let nf_key = NullifierKey::new(Digest::default());

        let consumed_resource = Resource {
            logic_ref: *Impl::hash_bytes(TRIVIAL_RESOURCE_LOGIC_VK),
            label_ref: Digest::default(),
            quantity: 1u128,
            value_ref: Digest::default(),
            is_ephemeral: false,
            nonce: [0u8; 32],
            nk_commitment: nf_key.commit(),
            rand_seed: [0u8; 32],
        };

        let created_resource = Resource {
            logic_ref: *Impl::hash_bytes(TRIVIAL_RESOURCE_LOGIC_VK),
            label_ref: Digest::default(),
            quantity: 1u128,
            value_ref: Digest::default(),
            is_ephemeral: false,
            nonce: [0u8; 32],
            nk_commitment: nf_key.commit(),
            rand_seed: [0u8; 32],
        };

        let merkle_path = MerklePath::<COMMITMENT_TREE_DEPTH>::default();

        let rcv = Scalar::ONE;

        ComplianceWitness {
            consumed_resource,
            created_resource,
            ephemeral_root: Digest::default(),
            merkle_path,
            rcv,
            nf_key,
        }
    }
}

impl ComplianceInstance {
    pub fn delta_projective(&self) -> ProjectivePoint {
        let encoded_point = EncodedPoint::from_affine_coordinates(
            &self.delta_x.into(),
            &self.delta_y.into(),
            false,
        );
        ProjectivePoint::from_encoded_point(&encoded_point).unwrap()
    }

    pub fn delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(self.consumed_nullifier.as_bytes());
        msg.extend_from_slice(self.created_commitment.as_bytes());
        msg
    }
}

#[test]
fn test_compliance_instance_encoding() {
    let instance = ComplianceInstance::default();

    let encoded = bincode::serialize(&instance).unwrap();
    println!("Encoded instance: {:?}", encoded);
    assert!(encoded.len() == 224);
}
