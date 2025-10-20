use crate::utils::{bytes_to_words, hash_two, words_to_bytes};
use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::sha::{Digest, DIGEST_WORDS};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::ByteBuf;
lazy_static! {
    pub static ref PADDING_LEAF: Digest =
        Digest::from_hex("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06")
            .unwrap();
}

/// A path from a position in a particular commitment tree to the root of that tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePath(
    #[serde(
        deserialize_with = "deserialize_merkle_path",
        serialize_with = "serialize_merkle_path"
    )]
    pub Vec<(Vec<u32>, bool)>,
);

pub fn serialize_merkle_path<S>(t: &[(Vec<u32>, bool)], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    t.iter()
        .map(|(t, b)| (ByteBuf::from(words_to_bytes(t)), *b))
        .collect::<Vec<(ByteBuf, bool)>>()
        .serialize(s)
}

pub fn deserialize_merkle_path<'de, D>(deserializer: D) -> Result<Vec<(Vec<u32>, bool)>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Vec::<(ByteBuf, bool)>::deserialize(deserializer)?
        .into_iter()
        .map(|(t, b)| (bytes_to_words(&t.into_vec()), b))
        .collect())
}

impl MerklePath {
    /// Constructs a Merkle path directly from a path and position.
    pub fn from_path(auth_path: &[(Vec<u32>, bool)]) -> Self {
        MerklePath(auth_path.to_vec())
    }

    /// Returns the root of the tree corresponding to this path applied to `leaf`.
    pub fn root(&self, leaf: &Digest) -> Vec<u32> {
        self.0
            .iter()
            .fold(
                leaf.as_words().to_vec(),
                |root, (p, leaf_is_on_right)| match leaf_is_on_right {
                    false => hash_two(&root, p),
                    true => hash_two(p, &root),
                },
            )
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for MerklePath {
    fn default() -> Self {
        MerklePath(vec![
            (vec![0u32; DIGEST_WORDS], false);
           10 // COMMITMENT_TREE_DEPTH, only for testing
        ])
    }
}
