use crate::digest::{hash_words, Digest, DIGEST_WORDS};
extern crate alloc;
use alloc::vec::Vec;

pub fn hash_two(left: &Digest, right: &Digest) -> Digest {
    let mut words = Vec::with_capacity(2 * DIGEST_WORDS);
    words.extend_from_slice(&left.to_words());
    words.extend_from_slice(&right.to_words());
    hash_words(&words)
}
