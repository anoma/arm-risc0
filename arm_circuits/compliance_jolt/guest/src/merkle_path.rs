extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use crate::digest::Digest;
use crate::utils::hash_two;

#[derive(Clone)]
pub struct MerklePath(pub Vec<(Digest, bool)>);

impl MerklePath {
    pub fn root(&self, leaf: &Digest) -> Digest {
        self.0.iter().fold(*leaf, |root, (p, is_right)| {
            if !is_right { hash_two(&root, p) } else { hash_two(p, &root) }
        })
    }
}
impl Default for MerklePath { fn default() -> Self { MerklePath(vec![(Digest::default(), false); 10]) } }
