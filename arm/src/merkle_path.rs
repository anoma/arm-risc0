use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::sha::{Digest, Impl, Sha256, DIGEST_BYTES};
use rustler::types::map::map_new;
use rustler::{Decoder, NifResult};
#[cfg(feature = "nif")]
use rustler::{Env, Term};
use serde::{Deserialize, Serialize};

lazy_static! {
    pub static ref PADDING_LEAVE: Digest =
        Digest::from_hex("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06")
            .unwrap();
}
pub const COMMITMENT_TREE_DEPTH: usize = 32;

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
        *PADDING_LEAVE
    }

    /// Returns the parent node within the tree of the two given nodes.
    fn combine(lhs: &Self, rhs: &Self) -> Self {
        let mut bytes = [0u8; 2 * DIGEST_BYTES];
        let mut offset: usize = 0;
        // Write the left child
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(lhs.as_ref());
        offset += DIGEST_BYTES;
        // Write the right child
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(rhs.as_ref());
        offset += DIGEST_BYTES;
        assert_eq!(offset, 2 * DIGEST_BYTES);
        // Now produce the hash
        *Impl::hash_bytes(&bytes)
    }
}

/// A path from a position in a particular commitment tree to the root of that tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// #[cfg_attr(feature = "nif", derive(NifStruct))]
// #[cfg_attr(feature = "nif", module = "Anoma.Arm.MerklePath")]
pub struct MerklePath<const TREE_DEPTH: usize> {
    auth_path: Vec<(Digest, bool)>,
}

    #[cfg(feature = "nif")]
    impl<const TREE_DEPTH: usize> rustler::Encoder for MerklePath<TREE_DEPTH> {
        fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
            let map = map_new(env);
            map
        }
    }

    #[cfg(feature = "nif")]
    impl<'a, const TREE_DEPTH: usize> Decoder<'a> for MerklePath<TREE_DEPTH> {
        fn decode(term: Term<'a>) -> NifResult<Self> {
            Ok(MerklePath { auth_path: vec![] })
        }
    }

impl<const TREE_DEPTH: usize> MerklePath<TREE_DEPTH> {
    /// Constructs a Merkle path directly from a path and position.
    pub fn from_path(auth_path: [(Digest, bool); TREE_DEPTH]) -> Self {
        MerklePath {
            auth_path: auth_path.to_vec(),
        }
    }
    /// Returns the root of the tree corresponding to this path applied to `leaf`.
    pub fn root(&self, leaf: &Digest) -> Digest {
        if self.auth_path.len() != TREE_DEPTH {
            panic!("Merkle path length does not match TREE_DEPTH");
        }
        self.auth_path.iter().fold(
            *leaf,
            |root, (p, leaf_is_on_right)| match leaf_is_on_right {
                false => Digest::combine(&root, p),
                true => Digest::combine(p, &root),
            },
        )
    }
}

impl<const TREE_DEPTH: usize> Default for MerklePath<TREE_DEPTH> {
    fn default() -> Self {
        MerklePath {
            auth_path: vec![(Digest::default(), false); TREE_DEPTH],
        }
    }
}
