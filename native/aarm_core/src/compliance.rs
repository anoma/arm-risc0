use crate::{
    constants::TRIVIAL_RESOURCE_LOGIC_VK, merkle_path::MerklePath, nullifier_key::NullifierKey,
    resource::Resource,
};
use k256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field,
    },
    EncodedPoint, ProjectivePoint, Scalar,
};
use rand::Rng;
use risc0_zkvm::sha::{Digest, Impl, Sha256};
use serde_big_array::BigArray;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceInstance {
    pub nullifier: Digest,
    pub commitment: Digest,
    pub merkle_root: Digest,
    pub delta: EncodedPoint,
    pub consumed_logic_ref: Digest,
    pub created_logic_ref: Digest,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceWitness<const COMMITMENT_TREE_DEPTH: usize> {
    /// The consumed resource
    pub consumed_resource: Resource,
    /// The path from the consumed commitment to the root in the commitment tree
    #[serde(with = "BigArray")]
    pub merkle_path: [(Digest, bool); COMMITMENT_TREE_DEPTH],
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

impl<const COMMITMENT_TREE_DEPTH: usize> Default for ComplianceWitness<COMMITMENT_TREE_DEPTH> {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let nonce_1: [u8; 32] = rng.gen();
        let nonce_2: [u8; 32] = rng.gen();

        let nf_key = NullifierKey::new(Digest::default());

        let consumed_resource = Resource {
            logic_ref: *Impl::hash_bytes(TRIVIAL_RESOURCE_LOGIC_VK),
            label_ref: Digest::default(),
            quantity: 1u128,
            value_ref: Digest::default(),
            is_ephemeral: false,
            nonce: nonce_1,
            nk_commitment: nf_key.commit(),
            rand_seed: rng.gen(),
        };

        let created_resource = Resource {
            logic_ref: *Impl::hash_bytes(TRIVIAL_RESOURCE_LOGIC_VK),
            label_ref: Digest::default(),
            quantity: 1u128,
            value_ref: Digest::default(),
            is_ephemeral: false,
            nonce: nonce_2,
            nk_commitment: nf_key.commit(),
            rand_seed: rng.gen(),
        };

        let merkle_path: [(Digest, bool); COMMITMENT_TREE_DEPTH] =
            [(Digest::default(), false); COMMITMENT_TREE_DEPTH];

        let rcv = Scalar::random(rng);

        ComplianceWitness {
            consumed_resource,
            created_resource,
            merkle_path,
            rcv,
            nf_key,
        }
    }
}

pub struct ComplianceCircuit<const COMMITMENT_TREE_DEPTH: usize> {
    pub compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH>,
}

impl<const COMMITMENT_TREE_DEPTH: usize> ComplianceCircuit<COMMITMENT_TREE_DEPTH> {
    pub fn get_consumed_resource_logic(&self) -> Digest {
        self.compliance_witness.consumed_resource.logic_ref
    }

    pub fn get_created_resource_logic(&self) -> Digest {
        self.compliance_witness.created_resource.logic_ref
    }

    pub fn consumed_commitment(&self) -> Digest {
        self.compliance_witness.consumed_resource.commitment()
    }

    pub fn created_commitment(&self) -> Digest {
        self.compliance_witness.created_resource.commitment()
    }

    pub fn consumed_nullifier(&self, cm: &Digest) -> Digest {
        self.compliance_witness
            .consumed_resource
            .nullifier_from_commitment(&self.compliance_witness.nf_key, cm)
            .unwrap()
    }

    pub fn merkle_tree_root(&self, cm: Digest) -> Digest {
        MerklePath::from_path(self.compliance_witness.merkle_path).root(cm)
    }

    pub fn delta_commitment(&self) -> EncodedPoint {
        // Compute delta and make delta commitment public
        let delta = self.compliance_witness.consumed_resource.kind()
            * self.compliance_witness.consumed_resource.quantity_scalar()
            - self.compliance_witness.created_resource.kind()
                * self.compliance_witness.created_resource.quantity_scalar()
            + ProjectivePoint::GENERATOR * self.compliance_witness.rcv;

        delta.to_encoded_point(false)
    }
}

impl ComplianceInstance {
    pub fn delta_coordinates(&self) -> ([u8; 32], [u8; 32]) {
        let x = (*self.delta.x().unwrap()).into();
        let y = (*self.delta.y().unwrap()).into();
        (x, y)
    }

    pub fn delta_projective(&self) -> ProjectivePoint {
        ProjectivePoint::from_encoded_point(&self.delta).unwrap()
    }

    pub fn delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(self.nullifier.as_bytes());
        msg.extend_from_slice(self.commitment.as_bytes());
        msg
    }
}
