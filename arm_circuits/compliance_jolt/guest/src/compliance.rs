extern crate alloc;
use alloc::vec::Vec;
use crate::digest::Digest;
use crate::error::ArmError;
use crate::merkle_path::MerklePath;
use crate::nullifier_key::NullifierKey;
use crate::resource::{Resource, scalar_mul_generator};
use jolt_inlines_secp256k1::{Secp256k1Fr, Secp256k1Point};

const INITIAL_ROOT_HEX: &str = "cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06";

pub const INSTANCE_BYTES: usize = 5 * 32 + 2 * 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComplianceInstance {
    pub consumed_nullifier: Digest,
    pub consumed_logic_ref: Digest,
    pub consumed_commitment_tree_root: Digest,
    pub created_commitment: Digest,
    pub created_logic_ref: Digest,
    pub delta_x: [u64; 4],
    pub delta_y: [u64; 4],
}

impl ComplianceInstance {
    pub fn to_bytes(&self) -> [u8; INSTANCE_BYTES] {
        let mut out = [0u8; INSTANCE_BYTES];
        let mut o = 0;
        out[o..o+32].copy_from_slice(self.consumed_nullifier.as_bytes()); o += 32;
        out[o..o+32].copy_from_slice(self.consumed_logic_ref.as_bytes()); o += 32;
        out[o..o+32].copy_from_slice(self.consumed_commitment_tree_root.as_bytes()); o += 32;
        out[o..o+32].copy_from_slice(self.created_commitment.as_bytes()); o += 32;
        out[o..o+32].copy_from_slice(self.created_logic_ref.as_bytes()); o += 32;
        for limb in &self.delta_x { out[o..o+8].copy_from_slice(&limb.to_le_bytes()); o += 8; }
        for limb in &self.delta_y { out[o..o+8].copy_from_slice(&limb.to_le_bytes()); o += 8; }
        out
    }
}

#[derive(Clone)]
pub struct ComplianceWitness {
    pub consumed_resource: Resource,
    pub merkle_path: MerklePath,
    pub ephemeral_root: Digest,
    pub nf_key: NullifierKey,
    pub created_resource: Resource,
    pub rcv: Vec<u8>,
}

impl ComplianceWitness {
    pub fn constrain(&self) -> Result<ComplianceInstance, ArmError> {
        let consumed_cm = self.consumed_resource.commitment();
        let consumed_logic_ref = self.consumed_resource.logic_ref;
        let consumed_commitment_tree_root = if self.consumed_resource.is_ephemeral {
            self.ephemeral_root
        } else {
            self.merkle_path.root(&consumed_cm)
        };
        let consumed_nullifier = self.consumed_resource.nullifier_from_commitment(&self.nf_key, &consumed_cm)?;
        let created_logic_ref = self.created_resource.logic_ref;
        let created_commitment = self.created_resource.commitment();
        assert_eq!(self.created_resource.nonce, *consumed_nullifier.as_bytes(),
            "Created resource nonce must match consumed nullifier");
        let (delta_x, delta_y) = self.delta()?;
        Ok(ComplianceInstance {
            consumed_nullifier, consumed_logic_ref, consumed_commitment_tree_root,
            created_commitment, created_logic_ref, delta_x, delta_y,
        })
    }

    fn delta(&self) -> Result<([u64; 4], [u64; 4]), ArmError> {
        let rcv_array: [u8; 32] = self.rcv.as_slice().try_into().map_err(|_| ArmError::InvalidRcv)?;
        let rcv_limbs = be_bytes_to_u64_limbs(&rcv_array);
        let rcv_scalar = Secp256k1Fr::from_u64_arr_unchecked(&rcv_limbs);
        let consumed_kind = self.consumed_resource.kind()?;
        let created_kind = self.created_resource.kind()?;
        let term1 = scalar_mul_point(&created_kind, &self.created_resource.quantity_scalar());
        let term2 = scalar_mul_point(&consumed_kind, &self.consumed_resource.quantity_scalar());
        let term3 = scalar_mul_generator(&rcv_scalar);
        let delta = term1.add(&term2.neg()).add(&term3);
        Ok((delta.x().e(), delta.y().e()))
    }
}

fn be_bytes_to_u64_limbs(b: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_be_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]]),
        u64::from_be_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
        u64::from_be_bytes([b[8],  b[9],  b[10], b[11], b[12], b[13], b[14], b[15]]),
        u64::from_be_bytes([b[0],  b[1],  b[2],  b[3],  b[4],  b[5],  b[6],  b[7]]),
    ]
}

/// GLV-accelerated scalar multiplication: scalar * point.
fn scalar_mul_point(point: &Secp256k1Point, scalar: &Secp256k1Fr) -> Secp256k1Point {
    use crate::resource::scalar_mul_128;
    let [(k1_neg, k1_abs), (k2_neg, k2_abs)] = Secp256k1Point::decompose_scalar(scalar);
    let p_endo = point.endomorphism();
    let p1 = scalar_mul_128(point, k1_abs);
    let p1 = if k1_neg { p1.neg() } else { p1 };
    let p2 = scalar_mul_128(&p_endo, k2_abs);
    let p2 = if k2_neg { p2.neg() } else { p2 };
    p1.add(&p2)
}

impl Default for ComplianceWitness {
    fn default() -> Self {
        let initial_root = Digest::from_hex(INITIAL_ROOT_HEX).unwrap();
        let nf_key = NullifierKey::default();
        let consumed_resource = Resource {
            logic_ref: Digest::default(), label_ref: Digest::default(),
            quantity: 1u128, value_ref: Digest::default(), is_ephemeral: false,
            nonce: [0u8; 32], nk_commitment: nf_key.commit(), rand_seed: [0u8; 32],
        };
        let nf = consumed_resource.nullifier(&nf_key).unwrap();
        let created_resource = Resource {
            logic_ref: Digest::default(), label_ref: Digest::default(),
            quantity: 1u128, value_ref: Digest::default(), is_ephemeral: false,
            nonce: *nf.as_bytes(), nk_commitment: nf_key.commit(), rand_seed: [0u8; 32],
        };
        let mut rcv = [0u8; 32];
        rcv[31] = 1;
        ComplianceWitness {
            consumed_resource, created_resource, ephemeral_root: initial_root,
            merkle_path: MerklePath::default(), rcv: rcv.to_vec(), nf_key,
        }
    }
}
