extern crate alloc;
use alloc::vec::Vec;
use crate::digest::{hash_bytes, Digest, DIGEST_BYTES};
use crate::error::ArmError;
use crate::nullifier_key::{NullifierKey, NullifierKeyCommitment};
use jolt_inlines_secp256k1::{Secp256k1Fr, Secp256k1Point};

const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"RISC0_ExpandSeed";
const PRF_EXPAND_PSI: u8 = 0;
const PRF_EXPAND_RCM: u8 = 1;
const QUANTITY_BYTES: usize = 16;
const RESOURCE_BYTES: usize = DIGEST_BYTES * 6 + QUANTITY_BYTES + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resource {
    pub logic_ref: Digest,
    pub label_ref: Digest,
    pub quantity: u128,
    pub value_ref: Digest,
    pub is_ephemeral: bool,
    pub nonce: [u8; DIGEST_BYTES],
    pub nk_commitment: NullifierKeyCommitment,
    pub rand_seed: [u8; DIGEST_BYTES],
}

impl Resource {
    pub fn quantity_scalar(&self) -> Secp256k1Fr {
        let lo = self.quantity as u64;
        let hi = (self.quantity >> 64) as u64;
        Secp256k1Fr::from_u64_arr_unchecked(&[lo, hi, 0, 0])
    }

    /// Map (logic_ref, label_ref) to a secp256k1 point via hash-to-scalar * G.
    /// NOTE: for benchmarking. Production needs proper hash-to-curve.
    pub fn kind(&self) -> Result<Secp256k1Point, ArmError> {
        let mut bytes = [0u8; DIGEST_BYTES * 2];
        bytes[0..DIGEST_BYTES].copy_from_slice(self.logic_ref.as_ref());
        bytes[DIGEST_BYTES..DIGEST_BYTES * 2].copy_from_slice(self.label_ref.as_ref());
        let hash = hash_bytes(&bytes);
        let b = hash.as_bytes();
        let limbs = [
            u64::from_be_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]]),
            u64::from_be_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
            u64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        ];
        let scalar = Secp256k1Fr::from_u64_arr_unchecked(&limbs);
        Ok(scalar_mul_generator(&scalar))
    }

    fn prf_expand(&self, tag: u8) -> Vec<u8> {
        let mut bytes = [0u8; 16 + 1 + 2 * DIGEST_BYTES];
        let mut o = 0;
        bytes[o..o + 16].copy_from_slice(PRF_EXPAND_PERSONALIZATION); o += 16;
        bytes[o] = tag; o += 1;
        bytes[o..o + DIGEST_BYTES].copy_from_slice(&self.rand_seed); o += DIGEST_BYTES;
        bytes[o..o + DIGEST_BYTES].copy_from_slice(&self.nonce);
        hash_bytes(&bytes).as_bytes().to_vec()
    }

    fn psi(&self) -> Vec<u8> { self.prf_expand(PRF_EXPAND_PSI) }
    fn rcm(&self) -> Vec<u8> { self.prf_expand(PRF_EXPAND_RCM) }

    pub fn commitment(&self) -> Digest {
        let mut bytes = [0u8; RESOURCE_BYTES];
        let mut o = 0;
        bytes[o..o + DIGEST_BYTES].copy_from_slice(self.logic_ref.as_ref()); o += DIGEST_BYTES;
        bytes[o..o + DIGEST_BYTES].copy_from_slice(self.label_ref.as_ref()); o += DIGEST_BYTES;
        bytes[o..o + QUANTITY_BYTES].copy_from_slice(&self.quantity.to_be_bytes()); o += QUANTITY_BYTES;
        bytes[o..o + DIGEST_BYTES].copy_from_slice(self.value_ref.as_ref()); o += DIGEST_BYTES;
        bytes[o] = self.is_ephemeral as u8; o += 1;
        bytes[o..o + DIGEST_BYTES].copy_from_slice(&self.nonce); o += DIGEST_BYTES;
        bytes[o..o + DIGEST_BYTES].copy_from_slice(self.nk_commitment.inner().as_ref()); o += DIGEST_BYTES;
        bytes[o..o + DIGEST_BYTES].copy_from_slice(&self.rcm());
        hash_bytes(&bytes)
    }

    pub fn nullifier(&self, nf_key: &NullifierKey) -> Result<Digest, ArmError> {
        let cm = self.commitment();
        self.nullifier_from_commitment(nf_key, &cm)
    }

    pub fn nullifier_from_commitment(&self, nf_key: &NullifierKey, cm: &Digest) -> Result<Digest, ArmError> {
        if self.nk_commitment == nf_key.commit() {
            let mut bytes = [0u8; 4 * DIGEST_BYTES];
            let mut o = 0;
            bytes[o..o + DIGEST_BYTES].copy_from_slice(nf_key.inner()); o += DIGEST_BYTES;
            bytes[o..o + DIGEST_BYTES].copy_from_slice(&self.nonce); o += DIGEST_BYTES;
            bytes[o..o + DIGEST_BYTES].copy_from_slice(&self.psi()); o += DIGEST_BYTES;
            bytes[o..o + DIGEST_BYTES].copy_from_slice(cm.as_bytes());
            Ok(hash_bytes(&bytes))
        } else {
            Err(ArmError::InvalidNullifierKey)
        }
    }
}

/// GLV-accelerated scalar multiplication: scalar * G.
/// Uses the secp256k1 endomorphism to halve the number of doublings.
pub fn scalar_mul_generator(scalar: &Secp256k1Fr) -> Secp256k1Point {
    let [(k1_neg, k1_abs), (k2_neg, k2_abs)] = Secp256k1Point::decompose_scalar(scalar);
    let g = Secp256k1Point::generator();
    let g_endo = g.endomorphism(); // lambda * G

    let p1 = scalar_mul_128(&g, k1_abs);
    let p1 = if k1_neg { p1.neg() } else { p1 };
    let p2 = scalar_mul_128(&g_endo, k2_abs);
    let p2 = if k2_neg { p2.neg() } else { p2 };
    p1.add(&p2)
}

/// Scalar multiplication with a 128-bit scalar using double-and-add.
pub fn scalar_mul_128(point: &Secp256k1Point, scalar: u128) -> Secp256k1Point {
    let mut result = Secp256k1Point::infinity();
    let mut base = point.clone();
    let lo = scalar as u64;
    let hi = (scalar >> 64) as u64;
    let mut bits = lo;
    for _ in 0..64 {
        if bits & 1 == 1 { result = result.add(&base); }
        base = base.double();
        bits >>= 1;
    }
    bits = hi;
    for _ in 0..64 {
        if bits & 1 == 1 { result = result.add(&base); }
        base = base.double();
        bits >>= 1;
    }
    result
}

impl Default for Resource {
    fn default() -> Self {
        Self {
            logic_ref: Digest::default(), label_ref: Digest::default(),
            quantity: 0, value_ref: Digest::default(), is_ephemeral: true,
            nonce: [0; DIGEST_BYTES], nk_commitment: NullifierKeyCommitment::default(),
            rand_seed: [0; DIGEST_BYTES],
        }
    }
}
