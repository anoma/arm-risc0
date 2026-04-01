extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use openvm_algebra_guest::IntMod;
use openvm_ecc_guest::{weierstrass::WeierstrassPoint, Group};
use openvm_k256::{Secp256k1Coord, Secp256k1Point};
use openvm_sha2::sha256;

const DIGEST_BYTES: usize = 32;
const QUANTITY_BYTES: usize = 16;
const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"RISC0_ExpandSeed";
const INITIAL_ROOT_HEX: &str = "cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06";
const RESOURCE_BYTES: usize = DIGEST_BYTES * 6 + QUANTITY_BYTES + 1;

// ---- Digest ----
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Digest([u8; DIGEST_BYTES]);

impl Digest {
    pub fn as_bytes(&self) -> &[u8; DIGEST_BYTES] { &self.0 }
    pub fn from_hex(s: &str) -> Self {
        let bytes = hex::decode(s).unwrap();
        let mut arr = [0u8; DIGEST_BYTES];
        arr.copy_from_slice(&bytes);
        Digest(arr)
    }
}
impl Default for Digest { fn default() -> Self { Digest([0u8; DIGEST_BYTES]) } }
impl From<[u8; DIGEST_BYTES]> for Digest { fn from(b: [u8; DIGEST_BYTES]) -> Self { Digest(b) } }

fn hash_bytes(data: &[u8]) -> Digest {
    let h = sha256(data);
    let mut out = [0u8; DIGEST_BYTES];
    out.copy_from_slice(&h);
    Digest(out)
}

fn hash_two(left: &Digest, right: &Digest) -> Digest {
    let mut combined = [0u8; 2 * DIGEST_BYTES];
    combined[..DIGEST_BYTES].copy_from_slice(&left.0);
    combined[DIGEST_BYTES..].copy_from_slice(&right.0);
    hash_bytes(&combined)
}

// ---- NullifierKey ----
#[derive(Clone, PartialEq, Eq)]
pub struct NullifierKey([u8; DIGEST_BYTES]);

impl NullifierKey {
    pub fn commit(&self) -> Digest { hash_bytes(&self.0) }
    pub fn inner(&self) -> &[u8] { &self.0 }
    pub fn from_bytes(b: [u8; DIGEST_BYTES]) -> Self { NullifierKey(b) }
}
impl Default for NullifierKey { fn default() -> Self { NullifierKey([0u8; DIGEST_BYTES]) } }

// ---- Resource ----
#[derive(Clone)]
pub struct Resource {
    pub logic_ref: Digest,
    pub label_ref: Digest,
    pub quantity: u128,
    pub value_ref: Digest,
    pub is_ephemeral: bool,
    pub nonce: [u8; DIGEST_BYTES],
    pub nk_commitment: Digest,
    pub rand_seed: [u8; DIGEST_BYTES],
}

impl Resource {
    fn prf_expand(&self, tag: u8) -> Digest {
        let mut bytes = [0u8; 16 + 1 + 2 * DIGEST_BYTES];
        bytes[0..16].copy_from_slice(PRF_EXPAND_PERSONALIZATION);
        bytes[16] = tag;
        bytes[17..17 + DIGEST_BYTES].copy_from_slice(&self.rand_seed);
        bytes[17 + DIGEST_BYTES..].copy_from_slice(&self.nonce);
        hash_bytes(&bytes)
    }

    pub fn commitment(&self) -> Digest {
        let rcm = self.prf_expand(1);
        let mut bytes = [0u8; RESOURCE_BYTES];
        let mut o = 0;
        bytes[o..o+32].copy_from_slice(self.logic_ref.as_bytes()); o += 32;
        bytes[o..o+32].copy_from_slice(self.label_ref.as_bytes()); o += 32;
        bytes[o..o+16].copy_from_slice(&self.quantity.to_be_bytes()); o += 16;
        bytes[o..o+32].copy_from_slice(self.value_ref.as_bytes()); o += 32;
        bytes[o] = self.is_ephemeral as u8; o += 1;
        bytes[o..o+32].copy_from_slice(&self.nonce); o += 32;
        bytes[o..o+32].copy_from_slice(self.nk_commitment.as_bytes()); o += 32;
        bytes[o..o+32].copy_from_slice(rcm.as_bytes());
        hash_bytes(&bytes)
    }

    pub fn nullifier(&self, nf_key: &NullifierKey) -> Digest {
        let cm = self.commitment();
        self.nullifier_from_commitment(nf_key, &cm)
    }

    pub fn nullifier_from_commitment(&self, nf_key: &NullifierKey, cm: &Digest) -> Digest {
        assert!(self.nk_commitment == nf_key.commit(), "invalid nullifier key");
        let psi = self.prf_expand(0);
        let mut bytes = [0u8; 4 * DIGEST_BYTES];
        bytes[0..32].copy_from_slice(nf_key.inner());
        bytes[32..64].copy_from_slice(&self.nonce);
        bytes[64..96].copy_from_slice(psi.as_bytes());
        bytes[96..128].copy_from_slice(cm.as_bytes());
        hash_bytes(&bytes)
    }

    /// RFC 9380 hash-to-curve (OSSWU + 3-isogeny)
    pub fn kind(&self) -> Secp256k1Point {
        let mut bytes = [0u8; 2 * DIGEST_BYTES];
        bytes[..DIGEST_BYTES].copy_from_slice(self.logic_ref.as_bytes());
        bytes[DIGEST_BYTES..].copy_from_slice(self.label_ref.as_bytes());
        crate::hash_to_curve::hash_to_curve(&bytes)
    }

    pub fn quantity_bytes_le(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..16].copy_from_slice(&self.quantity.to_le_bytes());
        b
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RESOURCE_BYTES);
        out.extend_from_slice(self.logic_ref.as_bytes());
        out.extend_from_slice(self.label_ref.as_bytes());
        out.extend_from_slice(&self.quantity.to_be_bytes());
        out.extend_from_slice(self.value_ref.as_bytes());
        out.push(self.is_ephemeral as u8);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(self.nk_commitment.as_bytes());
        out.extend_from_slice(&self.rand_seed);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        let mut o = 0usize;
        let read32 = |o: &mut usize| -> [u8; 32] {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&data[*o..*o+32]);
            *o += 32;
            buf
        };
        let logic_ref = Digest::from(read32(&mut o));
        let label_ref = Digest::from(read32(&mut o));
        let mut qty = [0u8; 16];
        qty.copy_from_slice(&data[o..o+16]); o += 16;
        let quantity = u128::from_be_bytes(qty);
        let value_ref = Digest::from(read32(&mut o));
        let is_ephemeral = data[o] != 0; o += 1;
        let nonce = read32(&mut o);
        let nk_commitment = Digest::from(read32(&mut o));
        let rand_seed = read32(&mut o);
        Resource { logic_ref, label_ref, quantity, value_ref, is_ephemeral, nonce, nk_commitment, rand_seed }
    }
}

// ---- ComplianceInstance ----
pub struct ComplianceInstance {
    pub consumed_nullifier: Digest,
    pub consumed_logic_ref: Digest,
    pub consumed_commitment_tree_root: Digest,
    pub created_commitment: Digest,
    pub created_logic_ref: Digest,
    pub delta_x: [u8; 32],
    pub delta_y: [u8; 32],
}

impl ComplianceInstance {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(7 * 32);
        out.extend_from_slice(self.consumed_nullifier.as_bytes());
        out.extend_from_slice(self.consumed_logic_ref.as_bytes());
        out.extend_from_slice(self.consumed_commitment_tree_root.as_bytes());
        out.extend_from_slice(self.created_commitment.as_bytes());
        out.extend_from_slice(self.created_logic_ref.as_bytes());
        out.extend_from_slice(&self.delta_x);
        out.extend_from_slice(&self.delta_y);
        out
    }
}

// ---- ComplianceWitness ----
pub struct ComplianceWitness {
    pub consumed_resource: Resource,
    pub created_resource: Resource,
    pub ephemeral_root: Digest,
    pub nf_key: NullifierKey,
    pub merkle_path: Vec<(Digest, bool)>,
    pub rcv: [u8; 32],
}

impl ComplianceWitness {
    pub fn constrain(&self) -> ComplianceInstance {
        let consumed_cm = self.consumed_resource.commitment();
        let consumed_logic_ref = self.consumed_resource.logic_ref;
        let consumed_commitment_tree_root = if self.consumed_resource.is_ephemeral {
            self.ephemeral_root
        } else {
            self.merkle_path.iter().fold(consumed_cm, |root, (p, is_right)| {
                if !is_right { hash_two(&root, p) } else { hash_two(p, &root) }
            })
        };
        let consumed_nullifier = self.consumed_resource.nullifier_from_commitment(&self.nf_key, &consumed_cm);
        let created_logic_ref = self.created_resource.logic_ref;
        let created_commitment = self.created_resource.commitment();

        assert_eq!(self.created_resource.nonce, *consumed_nullifier.as_bytes(),
            "Created resource nonce must match consumed nullifier");

        let (delta_x, delta_y) = self.delta();
        ComplianceInstance {
            consumed_nullifier, consumed_logic_ref, consumed_commitment_tree_root,
            created_commitment, created_logic_ref, delta_x, delta_y,
        }
    }

    fn delta(&self) -> ([u8; 32], [u8; 32]) {
        let consumed_kind = self.consumed_resource.kind();
        let created_kind = self.created_resource.kind();

        let term1 = scalar_mul(&created_kind, &self.created_resource.quantity_bytes_le());
        let term2 = scalar_mul(&consumed_kind, &self.consumed_resource.quantity_bytes_le());
        let term3 = scalar_mul_generator(&self.rcv);

        // term1 - term2 + term3
        let neg_term2 = -term2;
        let delta = &(&term1 + &neg_term2) + &term3;

        let (x, y) = delta.into_coords();
        let mut dx = [0u8; 32];
        let mut dy = [0u8; 32];
        dx.copy_from_slice(x.to_be_bytes().as_ref());
        dy.copy_from_slice(y.to_be_bytes().as_ref());
        (dx, dy)
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        let mut o = 0usize;
        let consumed_resource = Resource::from_bytes(&data[o..]); o += RESOURCE_BYTES;
        let created_resource = Resource::from_bytes(&data[o..]); o += RESOURCE_BYTES;
        let mut eph = [0u8; DIGEST_BYTES];
        eph.copy_from_slice(&data[o..o+DIGEST_BYTES]); o += DIGEST_BYTES;
        let mut nk = [0u8; DIGEST_BYTES];
        nk.copy_from_slice(&data[o..o+DIGEST_BYTES]); o += DIGEST_BYTES;
        let path_len = data[o] as usize; o += 1;
        let mut path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            let mut d = [0u8; DIGEST_BYTES];
            d.copy_from_slice(&data[o..o+DIGEST_BYTES]); o += DIGEST_BYTES;
            let is_right = data[o] != 0; o += 1;
            path.push((Digest::from(d), is_right));
        }
        let mut rcv = [0u8; 32];
        rcv.copy_from_slice(&data[o..o+32]);
        ComplianceWitness {
            consumed_resource, created_resource,
            ephemeral_root: Digest::from(eph),
            nf_key: NullifierKey::from_bytes(nk),
            merkle_path: path, rcv,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.consumed_resource.to_bytes());
        out.extend_from_slice(&self.created_resource.to_bytes());
        out.extend_from_slice(self.ephemeral_root.as_bytes());
        out.extend_from_slice(self.nf_key.inner());
        out.push(self.merkle_path.len() as u8);
        for (d, is_right) in &self.merkle_path {
            out.extend_from_slice(d.as_bytes());
            out.push(*is_right as u8);
        }
        out.extend_from_slice(&self.rcv);
        out
    }
}

impl Default for ComplianceWitness {
    fn default() -> Self {
        let initial_root = Digest::from_hex(INITIAL_ROOT_HEX);
        let nf_key = NullifierKey::default();
        let consumed_resource = Resource {
            logic_ref: Digest::default(), label_ref: Digest::default(),
            quantity: 1u128, value_ref: Digest::default(), is_ephemeral: false,
            nonce: [0u8; 32], nk_commitment: nf_key.commit(), rand_seed: [0u8; 32],
        };
        let nf = consumed_resource.nullifier(&nf_key);
        let created_resource = Resource {
            logic_ref: Digest::default(), label_ref: Digest::default(),
            quantity: 1u128, value_ref: Digest::default(), is_ephemeral: false,
            nonce: *nf.as_bytes(), nk_commitment: nf_key.commit(), rand_seed: [0u8; 32],
        };
        let mut rcv = [0u8; 32];
        rcv[0] = 1;
        ComplianceWitness {
            consumed_resource, created_resource, ephemeral_root: initial_root,
            nf_key, merkle_path: vec![(Digest::default(), false); 10], rcv,
        }
    }
}

// ---- EC helpers using OpenVM accelerated ops ----

/// Double-and-add scalar mul using OpenVM accelerated point ops
fn scalar_mul(point: &Secp256k1Point, scalar_le: &[u8; 32]) -> Secp256k1Point {
    let mut result = <Secp256k1Point as WeierstrassPoint>::IDENTITY;
    let mut base = point.clone();
    for byte_idx in 0..32 {
        let byte = scalar_le[byte_idx];
        for bit in 0..8 {
            if (byte >> bit) & 1 == 1 {
                result = &result + &base;
            }
            base = base.double();
        }
    }
    result
}

fn scalar_mul_generator(scalar_le: &[u8; 32]) -> Secp256k1Point {
    // secp256k1 generator
    let gx = Secp256k1Coord::from_be_bytes_unchecked(&[
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
        0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
        0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
        0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
    ]);
    let gy = Secp256k1Coord::from_be_bytes_unchecked(&[
        0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
        0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
        0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
        0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
    ]);
    let g = Secp256k1Point::from_xy_nonidentity(gx, gy).unwrap();
    scalar_mul(&g, scalar_le)
}
