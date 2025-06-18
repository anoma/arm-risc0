use crate::{
    constants::INITIAL_ROOT, merkle_path::MerklePath, nullifier_key::NullifierKey,
    resource::Resource,
};
use k256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field,
    },
    EncodedPoint, ProjectivePoint, Scalar,
};

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ComplianceInstance {
    pub consumed_nullifier: Vec<u8>,
    pub consumed_logic_ref: Vec<u8>,
    pub consumed_commitment_tree_root: Vec<u8>,
    pub created_commitment: Vec<u8>,
    pub created_logic_ref: Vec<u8>,
    pub delta_x: Vec<u8>,
    pub delta_y: Vec<u8>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceWitness<const COMMITMENT_TREE_DEPTH: usize> {
    /// The consumed resource
    pub consumed_resource: Resource,
    /// The path from the consumed commitment to the root in the commitment tree
    pub merkle_path: MerklePath<COMMITMENT_TREE_DEPTH>,
    /// The existing root for the ephemeral resource
    pub ephemeral_root: Vec<u8>,
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
            ephemeral_root: INITIAL_ROOT.as_bytes().to_vec(),
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
            ephemeral_root: vec![0; 32], // not used
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
            ephemeral_root: INITIAL_ROOT.as_bytes().to_vec(),
        }
    }

    pub fn constrain(&self) -> ComplianceInstance {
        let consumed_cm = self.consumed_commitment();
        let consumed_logic_ref = self.consumed_resource_logic();
        let consumed_commitment_tree_root = self.consumed_commitment_tree_root(&consumed_cm);

        let consumed_nullifier = self.consumed_nullifier(&consumed_cm);
        let created_logic_ref = self.created_resource_logic();
        let created_commitment = self.created_commitment();

        let (delta_x, delta_y) = self.delta_commitment();

        ComplianceInstance {
            consumed_nullifier,
            consumed_logic_ref,
            consumed_commitment_tree_root,
            created_commitment,
            created_logic_ref,
            delta_x,
            delta_y,
        }
    }

    pub fn consumed_resource_logic(&self) -> Vec<u8> {
        self.consumed_resource.logic_ref.clone()
    }

    pub fn created_resource_logic(&self) -> Vec<u8> {
        self.created_resource.logic_ref.clone()
    }

    pub fn consumed_commitment(&self) -> Vec<u8> {
        self.consumed_resource.commitment()
    }

    pub fn created_commitment(&self) -> Vec<u8> {
        self.created_resource.commitment()
    }

    pub fn consumed_nullifier(&self, cm: &[u8]) -> Vec<u8> {
        self.consumed_resource
            .nullifier_from_commitment(&self.nf_key, cm)
            .unwrap()
    }

    pub fn consumed_commitment_tree_root(&self, cm: &[u8]) -> Vec<u8> {
        if self.consumed_resource.is_ephemeral {
            self.ephemeral_root.clone()
        } else {
            self.merkle_path.root(cm)
        }
    }

    pub fn delta_commitment(&self) -> (Vec<u8>, Vec<u8>) {
        // Compute delta and make delta commitment public
        let delta = self.consumed_resource.kind() * self.consumed_resource.quantity_scalar()
            - self.created_resource.kind() * self.created_resource.quantity_scalar()
            + ProjectivePoint::GENERATOR * self.rcv;

        let encoded_delta = delta.to_encoded_point(false);
        (
            encoded_delta.x().unwrap().to_vec(),
            encoded_delta.y().unwrap().to_vec(),
        )
    }
}

impl<const COMMITMENT_TREE_DEPTH: usize> Default for ComplianceWitness<COMMITMENT_TREE_DEPTH> {
    fn default() -> Self {
        let nf_key = NullifierKey::default();

        let consumed_resource = Resource {
            logic_ref: vec![0; 32],
            label_ref: vec![0; 32],
            quantity: 1u128,
            value_ref: vec![0; 32],
            is_ephemeral: false,
            nonce: vec![0; 32],
            nk_commitment: nf_key.commit(),
            rand_seed: vec![0; 32],
        };

        let created_resource = Resource {
            logic_ref: vec![0; 32],
            label_ref: vec![0; 32],
            quantity: 1u128,
            value_ref: vec![0; 32],
            is_ephemeral: false,
            nonce: vec![0; 32],
            nk_commitment: nf_key.commit(),
            rand_seed: vec![0; 32],
        };

        let merkle_path = MerklePath::<COMMITMENT_TREE_DEPTH>::default();

        let rcv = Scalar::ONE;

        ComplianceWitness {
            consumed_resource,
            created_resource,
            ephemeral_root: vec![0; 32],
            merkle_path,
            rcv,
            nf_key,
        }
    }
}

impl ComplianceInstance {
    pub fn delta_projective(&self) -> ProjectivePoint {
        let x: [u8; 32] = self
            .delta_x
            .clone()
            .try_into()
            .expect("delta_x must be 32 bytes");
        let y: [u8; 32] = self
            .delta_y
            .clone()
            .try_into()
            .expect("delta_y must be 32 bytes");
        let encoded_point = EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
        ProjectivePoint::from_encoded_point(&encoded_point).unwrap()
    }

    pub fn delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.consumed_nullifier);
        msg.extend_from_slice(&self.created_commitment);
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
