#![no_std]
use risc0_zkvm::sha::Digest;
use risc0_zkvm::sha::DIGEST_BYTES;
use risc0_zkvm::sha::{Impl, Sha256};
use serde_big_array::BigArray;
use starknet_crypto::pedersen_hash;
use starknet_crypto::FieldElement;

/// Nullifier secret key
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Nsk(Digest);

impl Nsk {
    /// Compute the corresponding nullifier public key
    pub fn public_key(&self) -> Npk {
        let bytes: [u8; DIGEST_BYTES] = *self.0.as_ref();
        Npk(*Impl::hash_bytes(&bytes))
    }
}

/// Nullifier public key
#[derive(Clone, Eq, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub struct Npk(Digest);

const LABEL_BYTES: usize = 32;

const FUNGIBLE_BYTES: usize = 32;

const RSEED_BYTES: usize = 32;

const FELT_BYTES: usize = 32;

const RESOURCE_BYTES: usize =
    DIGEST_BYTES + LABEL_BYTES + FELT_BYTES + FUNGIBLE_BYTES + 1 + 4 + DIGEST_BYTES + RSEED_BYTES;

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
    pub v: [u8; FUNGIBLE_BYTES],
    // flag that reflects the resource ephemerality
    pub eph: bool,
    // guarantees the uniqueness of the resource computable components
    pub nonce: u32,
    // nullifier public key
    pub npk: Npk,
    // randomness seed used to derive whatever randomness neede
    pub rseed: [u8; RSEED_BYTES],
}

impl Resource {
    // Number representing the quantity of the resource
    pub fn quantity(&self) -> FieldElement {
        // Convert to a field element
        FieldElement::from_bytes_be(&self.quantity).unwrap()
    }

    // The kind is a function of the label and image ID. Must be infeasible to map different pairs to the same kind.
    pub fn kind(&self) -> FieldElement {
        // Concatenate the image ID and label
        let mut bytes = [0u8; DIGEST_BYTES + LABEL_BYTES];
        bytes[0..DIGEST_BYTES].clone_from_slice(self.image_id.as_ref());
        bytes[DIGEST_BYTES..DIGEST_BYTES + LABEL_BYTES].clone_from_slice(&self.label);
        // Hash the concatenation
        let mut digest: [u8; DIGEST_BYTES] = *(*Impl::hash_bytes(&bytes)).as_ref();
        // Chop out the first 5 bits of the hash
        digest[0] &= 0x07;
        // Convert to a field element
        FieldElement::from_bytes_be(&digest).unwrap()
    }

    // Resource deltas are used to reason about total quantities of different kinds of resources in transactions.
    pub fn delta(&self) -> FieldElement {
        pedersen_hash(&self.kind(), &self.quantity())
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
        bytes[offset..offset + FUNGIBLE_BYTES].clone_from_slice(&self.v);
        offset += FUNGIBLE_BYTES;
        // Write the ephemeral flag
        bytes[offset..offset + 1].clone_from_slice(&[self.eph as u8]);
        offset += 1;
        // Write the nonce bytes
        bytes[offset..offset + 4].clone_from_slice(&self.nonce.to_be_bytes());
        offset += 4;
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
            // Derive the nullifier
            Some(*Impl::hash_pair(&self.commitment(), &nsk.0))
        } else {
            None
        }
    }
}

/// A hashable node within a Merkle tree.
pub trait Hashable: Clone + Copy {
    /// Returns the parent node within the tree of the two given nodes.
    fn combine(_: usize, _: &Self, _: &Self) -> Self;

    /// Returns a blank leaf node.
    fn blank() -> Self;
}

impl Hashable for Digest {
    /// Returns a blank leaf node.
    fn blank() -> Self {
        Digest::default()
    }

    /// Returns the parent node within the tree of the two given nodes.
    fn combine(altitude: usize, lhs: &Self, rhs: &Self) -> Self {
        const USIZE_BYTES: usize = core::mem::size_of::<usize>();
        let mut bytes = [0u8; USIZE_BYTES + 2 * DIGEST_BYTES];
        let mut offset: usize = 0;
        // Write the altitude of the node
        bytes[offset..offset + USIZE_BYTES].clone_from_slice(&altitude.to_be_bytes());
        offset += core::mem::size_of::<usize>();
        // Write the left child
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&lhs.as_ref());
        offset += DIGEST_BYTES;
        // Write the right child
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&rhs.as_ref());
        offset += DIGEST_BYTES;
        assert_eq!(offset, USIZE_BYTES + 2 * DIGEST_BYTES);
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
    pub position: u64,
}

impl<const COMMITMENT_TREE_DEPTH: usize, Node> MerklePath<COMMITMENT_TREE_DEPTH, Node>
where
    Node: Hashable + serde::Serialize + for<'de2> serde::Deserialize<'de2>,
{
    /// Constructs a Merkle path directly from a path and position.
    pub fn from_path(auth_path: [(Node, bool); COMMITMENT_TREE_DEPTH], position: u64) -> Self {
        MerklePath {
            auth_path,
            position,
        }
    }

    /// Returns the root of the tree corresponding to this path applied to `leaf`.
    pub fn root(&self, leaf: Node) -> Node {
        self.auth_path
            .iter()
            .enumerate()
            .fold(
                leaf,
                |root, (i, (p, leaf_is_on_right))| match leaf_is_on_right {
                    false => Node::combine(i, &root, p),
                    true => Node::combine(i, p, &root),
                },
            )
    }
}

pub const COMMITMENT_TREE_DEPTH: usize = 32;

/// Input required for the consumption proof
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ConsumptionInput {
    // The resource that is being consumed
    pub resource: Resource,
    // The nullifier of the resource being consumed
    pub nsk: Nsk,
    // Indicates the route the path takes to the root
    pub path: MerklePath<COMMITMENT_TREE_DEPTH, Digest>,
}

/// Output of the consumption proof
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ConsumptionOutput {
    // The root of the Merkle tree in which the resource is anchored
    pub root: Digest,
    // The nullifier revealed by consuming the resource
    pub nullifier: Digest,
}

/// Input required for the creation proof
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CreationInput {
    // The resource that is being created
    pub resource: Resource,
}

/// Output of the creation proof
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CreationOutput {
    // The commitment of the created resource
    pub commitment: Digest,
}
