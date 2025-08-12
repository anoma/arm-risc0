use crate::merkle_path::{Hashable, MerklePath};
use risc0_zkvm::sha::{Digest, DIGEST_BYTES};
use rustler::types::map::map_new;
use rustler::{Atom, Decoder, Env, ListIterator, NifResult, Term};

pub const ACTION_TREE_MAX_NUM: usize = 1 << ACTION_TREE_DEPTH;
pub const ACTION_TREE_DEPTH: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
// #[cfg_attr(feature = "nif", derive(NifStruct))]
// #[cfg_attr(feature = "nif", module = "Anoma.Arm.MerkleTree")]
pub struct MerkleTree {
    leaves: Vec<Digest>,
}

#[cfg(feature = "nif")]
impl rustler::Encoder for MerkleTree {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let map = map_new(env);

        let map = map
            .map_put(
                Atom::from_str(env, "__struct__").unwrap(),
                Atom::from_str(env, "Elixir.Anoma.Arm.MerkleTree").unwrap(),
            )
            .unwrap();

        // encode the digests
        let bytes = self.leaves.iter().map(|d| d.as_bytes()).collect::<Vec<_>>();
        let term = bytes.encode(env);
        let map = map
            .map_put(Atom::from_str(env, "leaves").unwrap(), term)
            .unwrap();
        map
    }
}

#[cfg(feature = "nif")]
impl<'a> Decoder<'a> for MerkleTree {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let key = Atom::from_str(term.get_env(), "leaves")?;
        let value = term.map_get(key).expect("leaves not found in struct");
        let list_iterator: ListIterator = value.decode()?;

        let result: Vec<Digest> = list_iterator
            // Produces an iterator of NifResult<i64>
            .map(|x| {
                let digest_bytes: Vec<u8> = x.decode::<Vec<u8>>().unwrap();
                let digest_arr: [u8; DIGEST_BYTES] = digest_bytes.try_into().unwrap();
                let digest = Digest::from_bytes(digest_arr);
                let r: NifResult<Digest> = Ok(digest);
                r
            })
            .collect::<NifResult<Vec<Digest>>>()?;

        Ok(MerkleTree { leaves: result })
    }
}

impl MerkleTree {
    pub fn new(leaves: Vec<Digest>) -> Self {
        assert!(
            leaves.len() <= ACTION_TREE_MAX_NUM,
            "The number of leaves exceeds the ACTION_TREE_MAX_NUM"
        );
        MerkleTree { leaves }
    }

    pub fn insert(&mut self, value: Digest) {
        self.leaves.push(value)
    }

    pub fn root(&self) -> Digest {
        let mut cur_layer = self.leaves.clone();
        cur_layer.resize(ACTION_TREE_MAX_NUM, Digest::blank());
        while cur_layer.len() > 1 {
            cur_layer = cur_layer
                .chunks(2)
                .map(|pair| Digest::combine(&pair[0], &pair[1]))
                .collect();
        }
        cur_layer[0]
    }

    // Generate the merkle path for the current leave
    /// Generates the Merkle path for a given leaf in the Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `cur_leave` - The leaf value for which the Merkle path is to be generated.
    ///
    /// # Returns
    ///
    /// Returns an `Option` containing a `MerklePath` of depth `ACTION_TREE_DEPTH` if the leaf exists in the tree.
    /// The `MerklePath` is a vector of tuples, where each tuple contains:
    /// - A `Digest` representing the sibling node's hash.
    /// - A `bool` indicating whether the sibling is on the left (`true`) or right (`false`).
    ///
    /// Returns `None` if the leaf is not found in the tree.
    pub fn generate_path(&self, cur_leave: &Digest) -> Option<MerklePath<ACTION_TREE_DEPTH>> {
        let mut cur_layer = self.leaves.clone();
        cur_layer.resize(ACTION_TREE_MAX_NUM, Digest::blank());
        if let Some(position) = cur_layer.iter().position(|v| v == cur_leave) {
            let mut merkle_path = Vec::new();
            fn build_merkle_path_inner(
                cur_layer: Vec<Digest>,
                position: usize,
                path: &mut Vec<(Digest, bool)>,
            ) {
                if cur_layer.len() > 1 {
                    let sibling = {
                        let is_sibling_left = position % 2 != 0;
                        let sibling_value = if is_sibling_left {
                            cur_layer[position - 1]
                        } else {
                            cur_layer[position + 1]
                        };
                        (sibling_value, is_sibling_left)
                    };
                    path.push(sibling);

                    let prev_layer = cur_layer
                        .chunks(2)
                        .map(|pair| Digest::combine(&pair[0], &pair[1]))
                        .collect();

                    build_merkle_path_inner(prev_layer, position / 2, path);
                }
            }
            build_merkle_path_inner(cur_layer, position, &mut merkle_path);
            Some(MerklePath::<ACTION_TREE_DEPTH>::from_path(
                match merkle_path.try_into() {
                    Ok(path) => path,
                    Err(_) => return None, // Return None if the conversion fails
                },
            ))
        } else {
            None
        }
    }
}
