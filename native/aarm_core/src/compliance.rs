use crate::{
    constants::{DEFAULT_BYTES, TRIVIAL_RESOURCE_LOGIC_VK},
    merkle_path::MerklePath,
    nullifier::NullifierKey,
    resource::Resource,
};
use k256::{
    elliptic_curve::{group::GroupEncoding, Field},
    ProjectivePoint, Scalar,
};
use rand::Rng;
use risc0_zkvm::sha::{Digest, Impl, Sha256, DIGEST_WORDS};
use serde_big_array::BigArray;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceInstance {
    pub nullifier: Digest,
    pub commitment: Digest,
    pub merkle_root: Digest,
    pub delta: [u8; DEFAULT_BYTES],
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
        let label_ref: [u8; 32] = rng.gen();
        let nonce_1: [u8; 32] = rng.gen();
        let nonce_2: [u8; 32] = rng.gen();

        let nf_key = NullifierKey::new(Digest::default());
        const ONE: [u8; 32] = {
            let mut bytes = [0u8; DEFAULT_BYTES];
            bytes[0] = 1;
            bytes
        };

        let consumed_resource = Resource {
            logic_ref: *Impl::hash_bytes(TRIVIAL_RESOURCE_LOGIC_VK),
            label_ref,
            quantity: 1u128,
            value_ref: ONE,
            is_ephemeral: false,
            nonce: *Impl::hash_bytes(&nonce_1),
            nk_commitment: nf_key.commit(),
            rand_seed: rng.gen(),
        };

        let created_resource = Resource {
            logic_ref: *Impl::hash_bytes(TRIVIAL_RESOURCE_LOGIC_VK),
            label_ref,
            quantity: 1u128,
            value_ref: ONE,
            is_ephemeral: false,
            nonce: *Impl::hash_bytes(&nonce_2),
            nk_commitment: nf_key.commit(),
            rand_seed: rng.gen(),
        };

        let merkle_path: [(Digest, bool); COMMITMENT_TREE_DEPTH] =
            [(Digest::new([0; DIGEST_WORDS]), false); COMMITMENT_TREE_DEPTH];

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

    pub fn delta_commitment(&self) -> [u8; DEFAULT_BYTES] {
        // Compute delta and make delta commitment public
        let delta = self.compliance_witness.consumed_resource.kind()
            * self.compliance_witness.consumed_resource.quantity_scalar()
            - self.compliance_witness.created_resource.kind()
                * self.compliance_witness.created_resource.quantity_scalar()
            + ProjectivePoint::GENERATOR * self.compliance_witness.rcv;

        let delta_bytes: [u8; DEFAULT_BYTES] = delta.to_affine().to_bytes()[..DEFAULT_BYTES]
            .try_into()
            .expect("Slice length mismatch");
        delta_bytes
    }
}
