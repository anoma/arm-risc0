use k256::Scalar;
use risc0_zkvm::sha::Digest;
use serde_big_array::BigArray;

use crate::constants::DEFAULT_BYTES;
use crate::merkle_path::MerklePath;
use crate::nullifier::Nsk;
use crate::resource::Resource;
use k256::elliptic_curve::Field;
use rand::Rng;
use k256::{
    elliptic_curve::group::GroupEncoding,
    ProjectivePoint,
};
use risc0_zkvm::sha::{Sha256, Impl};
use crate::constants::{COMPRESSED_TRIVIAL_RESOURCE_LOGIC_VK, TREE_DEPTH};
use risc0_zkvm::sha::DIGEST_WORDS;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceInstance {
    pub input_nf: Digest,
    pub output_cm: Digest,
    pub input_resource_logic: Digest,
    pub output_resource_logic: Digest,
    pub merkle_root: Digest,
    pub delta: [u8; DEFAULT_BYTES],
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceWitness<const COMMITMENT_TREE_DEPTH: usize> {
    /// The input resource
    pub input_resource: Resource,
    /// The output resource
    pub output_resource: Resource,
    /// The path from the output commitment to the root in the resource commitment tree
    #[serde(with = "BigArray")]
    pub merkle_path: [(Digest, bool); COMMITMENT_TREE_DEPTH],
    /// Random scalar for delta commitment
    pub rcv: Scalar,
    /// Nullifier secret key
    pub nsk: Nsk,
    // TODO: If we want to add function privacy, include:
    // pub input_resource_logic_cm_r: [u8; DATA_BYTES],
    // pub output_resource_logic_cm_r: [u8; DATA_BYTES],
}

impl<const COMMITMENT_TREE_DEPTH: usize> ComplianceWitness<COMMITMENT_TREE_DEPTH> {
    pub fn default() -> ComplianceWitness<TREE_DEPTH> {
        let mut rng = rand::thread_rng();
        let label: [u8; 32] = rng.gen();
        let nonce_1: [u8; 32] = rng.gen();
        let nonce_2: [u8; 32] = rng.gen();

        let nsk = Nsk::new(Digest::default());
        const ONE: [u8; 32] = {
            let mut bytes = [0u8; DEFAULT_BYTES];
            bytes[0] = 1;
            bytes
        };

        let input_resource = Resource {
            logic: *Impl::hash_bytes(COMPRESSED_TRIVIAL_RESOURCE_LOGIC_VK),
            label,
            quantity: ONE,
            data: ONE,
            eph: false,
            nonce: *Impl::hash_bytes(&nonce_1),
            npk: nsk.public_key(),
            rseed: rng.gen(),
        };

        let output_resource = Resource {
            logic: *Impl::hash_bytes(COMPRESSED_TRIVIAL_RESOURCE_LOGIC_VK),
            label,
            quantity: ONE,
            data: ONE,
            eph: false,
            nonce: *Impl::hash_bytes(&nonce_2),
            npk: nsk.public_key(),
            rseed: rng.gen(),
        };

        let mut merkle_path: [(Digest, bool); TREE_DEPTH] =
            [(Digest::new([0; DIGEST_WORDS]), false); TREE_DEPTH];

        for i in 0..TREE_DEPTH {
            merkle_path[i] = (Digest::new([i as u32 + 1; DIGEST_WORDS]), i % 2 != 0);
        }

        let rcv = Scalar::random(rng);

        ComplianceWitness {
            input_resource,
            output_resource,
            merkle_path,
            rcv, 
            nsk,
        }
    }
}

pub struct ComplianceCircuit<const COMMITMENT_TREE_DEPTH: usize> {
   pub compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH>
}

impl<const COMMITMENT_TREE_DEPTH: usize> ComplianceCircuit<COMMITMENT_TREE_DEPTH> {
    pub fn input_resource_logic(&self) -> Digest {
        self.compliance_witness.input_resource.logic
    }

    pub fn input_resource_cm(&self) -> Digest {
        let nf = self.compliance_witness.input_resource.commitment();
        nf
    }

    pub fn input_resource_nf(&self) -> Digest {
        let nf = self.compliance_witness.input_resource.nullifier(self.compliance_witness.nsk).unwrap(); 
        nf
    }

    pub fn output_resource_logic(&self) -> Digest {
        self.compliance_witness.output_resource.logic
    }

    pub fn output_resource_cm(&self) -> Digest {
        let cm = self.compliance_witness.output_resource.commitment();
        cm
    }

    pub fn merkle_tree_root(&self, cm: Digest) -> Digest {
        let merkle_root = MerklePath::from_path(self.compliance_witness.merkle_path).root(cm);
        merkle_root
    }

    pub fn delta_commitment(&self) -> [u8; DEFAULT_BYTES] {
        // Compute delta and make delta commitment public
        // Comm(input_value - output_value)
        let delta = self.compliance_witness.input_resource.kind() * self.compliance_witness.input_resource.quantity()
            - self.compliance_witness.output_resource.kind() * self.compliance_witness.output_resource.quantity()
            + ProjectivePoint::GENERATOR * self.compliance_witness.rcv;

        let delta_bytes: [u8; DEFAULT_BYTES] = delta.to_affine().to_bytes()[..DEFAULT_BYTES]
            .try_into()
            .expect("Slice length mismatch");
        delta_bytes
    }
}
