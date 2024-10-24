#![no_std]
use k256::{
    elliptic_curve::{
        group::{ff::PrimeField, GroupEncoding},
        hash2curve::{ExpandMsgXmd, GroupDigest},
        Field,
    },
    ProjectivePoint, Scalar, Secp256k1,
};
use rand::Rng;
use risc0_zkvm::sha::{rust_crypto::Sha256 as Sha256Type, Digest, Impl, Sha256, DIGEST_BYTES};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";

const COMPRESSED_TRIVIAL_RESOURCE_LOGIC_VK: &[u8] = b"trivial_resource_logic_vk";

pub const TREE_DEPTH: usize = 32;

/// Nullifier secret key
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Nsk(Digest);

impl Nsk {
    pub fn new(nsk: Digest) -> Nsk {
        Nsk(nsk)
    }
    /// Compute the corresponding nullifier public key
    pub fn public_key(&self) -> Npk {
        let bytes: [u8; DIGEST_BYTES] = *self.0.as_ref();
        Npk(*Impl::hash_bytes(&bytes))
    }
}

/// Nullifier public key
#[derive(Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct Npk(Digest);

const LABEL_BYTES: usize = 32;

const FUNGIBLE_BYTES: usize = 32;

const RSEED_BYTES: usize = 32;

const FELT_BYTES: usize = 32;

const DATA_BYTES: usize = 32;

const RESOURCE_BYTES: usize = DIGEST_BYTES
    + LABEL_BYTES
    + FELT_BYTES
    + FUNGIBLE_BYTES
    + 1
    + DIGEST_BYTES
    + DIGEST_BYTES
    + RSEED_BYTES;

pub const DIGEST_WORDS: usize = 8;

/// A resource that can be created and consumed
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Resource {
    // a succinct representation of the predicate associated with the resource
    pub image_id: Digest,
    // specifies the fungibility domain for the resource
    pub label: [u8; LABEL_BYTES],
    // number representing the quantity of the resource
    pub quantity: [u8; FELT_BYTES],
    // the fungible data of the resource
    pub value: [u8; FUNGIBLE_BYTES],
    // flag that reflects the resource ephemerality
    pub eph: bool,
    // guarantees the uniqueness of the resource computable components
    pub nonce: Digest,
    // nullifier public key
    pub npk: Npk,
    // randomness seed used to derive whatever randomness needed
    pub rseed: [u8; RSEED_BYTES],
}

impl Resource {
    // Number representing the quantity of the resource
    pub fn quantity(&self) -> Scalar {
        // Convert to a field element
        Scalar::from_repr(self.quantity.into()).unwrap()
    }

    // The kind is a function of the label and image ID. Must be infeasible to map different pairs to the same kind.
    pub fn kind(&self) -> ProjectivePoint {
        // Concatenate the image ID and label
        let mut bytes = [0u8; DIGEST_BYTES + LABEL_BYTES];
        bytes[0..DIGEST_BYTES].clone_from_slice(self.image_id.as_ref());
        bytes[DIGEST_BYTES..DIGEST_BYTES + LABEL_BYTES].clone_from_slice(&self.label);
        // Hash to a curve point
        Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256Type>>(&[&bytes], &[DST]).unwrap()
    }

    pub fn psi(&self) -> Digest {
        let mut bytes = [0u8; 2 * DIGEST_BYTES];
        let mut offset: usize = 0;
        // Write the random seed
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&self.rseed.as_ref());
        offset += DIGEST_BYTES;
        // Write the nonce
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&self.nonce.as_ref());
        offset += DIGEST_BYTES;
        assert_eq!(offset, 2 * DIGEST_BYTES);
        *Impl::hash_bytes(&bytes)
    }

    // // Resource deltas are used to reason about total quantities of different kinds of resources in transactions.
    // pub fn delta(&self) -> FieldElement {
    //     pedersen_hash(&self.kind(), &self.quantity())
    // }
    pub fn rcm(&self) -> Digest {
        let mut bytes = [0u8; 2 * DIGEST_BYTES];
        let mut offset: usize = 1;
        // Write the random seed
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&self.rseed.as_ref());
        offset += DIGEST_BYTES;
        // Write the nonce
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&self.nonce.as_ref());
        offset += DIGEST_BYTES;
        assert_eq!(offset, 2 * DIGEST_BYTES);
        *Impl::hash_bytes(&bytes)
    }

    // Compute the commitment to the resource
    pub fn commitment(&self) -> Digest {
        // Concatenate all the components of this resource
        let mut bytes = [0u8; RESOURCE_BYTES];
        let mut offset: usize = 0;
        // Write the image ID bytes
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.image_id.as_ref());
        offset += DIGEST_BYTES;
        // Write the label bytes
        bytes[offset..offset + LABEL_BYTES].clone_from_slice(&self.label);
        offset += LABEL_BYTES;
        // Write the quantity bytes
        bytes[offset..offset + FELT_BYTES].clone_from_slice(&self.quantity);
        offset += FELT_BYTES;
        // Write the fungible data bytes
        bytes[offset..offset + FUNGIBLE_BYTES].clone_from_slice(&self.value);
        offset += FUNGIBLE_BYTES;
        // Write the ephemeral flag
        bytes[offset..offset + 1].clone_from_slice(&[self.eph as u8]);
        offset += 1;
        // Write the nonce bytes
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&self.nonce.as_ref());
        offset += DIGEST_BYTES;
        // Write the nullifier public key bytes
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.npk.0.as_ref());
        offset += DIGEST_BYTES;
        // Write the randomness seed bytes
        bytes[offset..offset + RSEED_BYTES].clone_from_slice(&self.rseed);
        offset += RSEED_BYTES;
        assert_eq!(offset, RESOURCE_BYTES);
        // Now produce the hash
        *Impl::hash_bytes(&bytes)
    }

    // Compute the nullifier of the resource
    pub fn nullifier(&self, nsk: Nsk) -> Option<Digest> {
        // Make sure that the nullifier public key corresponds to the secret key
        if self.npk == nsk.public_key() {
            let mut bytes = [0u8; 4 * DIGEST_BYTES];
            let mut offset: usize = 0;
            // Write the nullifier secret key
            bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&nsk.0.as_ref());
            offset += DIGEST_BYTES;
            // Write the nonce
            bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&self.nonce.as_ref());
            offset += DIGEST_BYTES;
            // Write psi
            bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&self.psi().as_ref());
            offset += DIGEST_BYTES;
            // Write the resource commitment
            bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&self.commitment().as_ref());
            offset += DIGEST_BYTES;

            assert_eq!(offset, 4 * DIGEST_BYTES);

            Some(*Impl::hash_bytes(&bytes))
        } else {
            None
        }
    }
}

/// A hashable node within a Merkle tree.
pub trait Hashable: Clone + Copy {
    /// Returns the parent node within the tree of the two given nodes.
    fn combine(_: &Self, _: &Self) -> Self;

    /// Returns a blank leaf node.
    fn blank() -> Self;
}

impl Hashable for Digest {
    /// Returns a blank leaf node.
    fn blank() -> Self {
        Digest::default()
    }

    /// Returns the parent node within the tree of the two given nodes.
    fn combine(lhs: &Self, rhs: &Self) -> Self {
        let mut bytes = [0u8; 2 * DIGEST_BYTES];
        let mut offset: usize = 0;
        // Write the left child
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&lhs.as_ref());
        offset += DIGEST_BYTES;
        // Write the right child
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&rhs.as_ref());
        offset += DIGEST_BYTES;
        assert_eq!(offset, 2 * DIGEST_BYTES);
        // Now produce the hash
        *Impl::hash_bytes(&bytes)
    }
}

/// A path from a position in a particular commitment tree to the root of that tree.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(bound = "Node: serde::Serialize, for<'de2> Node: serde::Deserialize<'de2>")]
pub struct MerklePath<const COMMITMENT_TREE_DEPTH: usize, Node>
where
    Node: serde::Serialize + for<'de2> serde::Deserialize<'de2>,
{
    #[serde(with = "BigArray")]
    pub auth_path: [(Node, bool); COMMITMENT_TREE_DEPTH],
}

impl<const COMMITMENT_TREE_DEPTH: usize, Node> MerklePath<COMMITMENT_TREE_DEPTH, Node>
where
    Node: Hashable + serde::Serialize + for<'de2> serde::Deserialize<'de2>,
{
    /// Constructs a Merkle path directly from a path and position.
    pub fn from_path(auth_path: [(Node, bool); COMMITMENT_TREE_DEPTH]) -> Self {
        MerklePath { auth_path }
    }

    /// Returns the root of the tree corresponding to this path applied to `leaf`.
    pub fn root(&self, leaf: Node) -> Node {
        self.auth_path
            .iter()
            .fold(leaf, |root, (p, leaf_is_on_right)| match leaf_is_on_right {
                false => Node::combine(&root, p),
                true => Node::combine(p, &root),
            })
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Compliance<const COMMITMENT_TREE_DEPTH: usize> {
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

impl<const COMMITMENT_TREE_DEPTH: usize> Compliance<COMMITMENT_TREE_DEPTH> {
    pub fn input_resource_logic(&self) -> Digest {
        self.input_resource.image_id
    }

    pub fn input_resource_cm(&self) -> Digest {
        let nf = self.input_resource.commitment();
        nf
    }

    pub fn input_resource_nf(&self) -> Digest {
        let nf = self.input_resource.nullifier(self.nsk).unwrap(); // Q: Do we want better error handling?
        nf
    }

    pub fn output_resource_logic(&self) -> Digest {
        self.output_resource.image_id
    }

    pub fn output_resource_cm(&self) -> Digest {
        let cm = self.output_resource.commitment();
        cm
    }

    pub fn merkle_tree_root(&self, cm: Digest) -> Digest {
        let merkle_root = MerklePath::from_path(self.merkle_path).root(cm);
        merkle_root
    }

    pub fn delta_commitment(&self) -> [u8; DATA_BYTES] {
        // Compute delta and make delta commitment public
        // Comm(input_value - output_value)
        let delta = self.input_resource.kind() * self.input_resource.quantity()
            - self.output_resource.kind() * self.output_resource.quantity()
            + ProjectivePoint::GENERATOR * self.rcv;

        let delta_bytes: [u8; DATA_BYTES] = delta.to_affine().to_bytes()[..DATA_BYTES]
            .try_into()
            .expect("Slice length mismatch");
        delta_bytes
    }

    pub fn default() -> Compliance<TREE_DEPTH> {
        let mut rng = rand::thread_rng();
        let label: [u8; 32] = rng.gen();
        let nonce_1: [u8; 32] = rng.gen();
        let nonce_2: [u8; 32] = rng.gen();

        let nsk = Nsk::new(Digest::default());
        const ONE: [u8; 32] = {
            let mut bytes = [0u8; FELT_BYTES];
            bytes[0] = 1;
            bytes
        };

        let input_resource = Resource {
            image_id: *Impl::hash_bytes(COMPRESSED_TRIVIAL_RESOURCE_LOGIC_VK),
            label,
            quantity: ONE,
            value: ONE,
            eph: false,
            nonce: *Impl::hash_bytes(&nonce_1),
            npk: nsk.public_key(),
            rseed: rng.gen(),
        };

        let output_resource = Resource {
            image_id: *Impl::hash_bytes(COMPRESSED_TRIVIAL_RESOURCE_LOGIC_VK),
            label,
            quantity: ONE,
            value: ONE,
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

        Compliance {
            input_resource,
            output_resource,
            merkle_path,
            rcv,
            nsk,
        }
    }
}
