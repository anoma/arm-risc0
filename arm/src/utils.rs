//! Utility functions for byte and word conversions and hashing.

use risc0_zkp::core::{
    digest::{DIGEST_WORDS, Digest},
    hash::sha::{Impl, Sha256},
};

/// Converts a byte slice to a vector of u32 words.
pub fn bytes_to_words(bytes: &[u8]) -> Vec<u32> {
    let mut words = Vec::new();
    let mut iter = bytes.chunks_exact(4);
    for chunk in iter.by_ref() {
        let mut word = 0u32;
        for &byte in chunk {
            word = (word << 8) | (byte as u32);
        }
        words.push(u32::from_be(word));
    }

    let rem = iter.remainder();
    if !rem.is_empty() {
        let mut arr = [0u8; 4];
        arr[..rem.len()].copy_from_slice(rem);
        let mut word = 0u32;
        for byte in arr {
            word = (word << 8) | (byte as u32);
        }
        words.push(u32::from_be(word));
    }
    words
}

/// Converts a slice of u32 words to a byte slice.
pub fn words_to_bytes(words: &[u32]) -> &[u8] {
    bytemuck::cast_slice(words)
}

/// Hashes two digests together using SHA-256.
pub fn hash_two(left: &Digest, right: &Digest) -> Digest {
    let mut words = Vec::with_capacity(2 * DIGEST_WORDS);
    words.extend_from_slice(left.as_words());
    words.extend_from_slice(right.as_words());
    *Impl::hash_words(&words)
}

/// Hashes arbitrary bytes using SHA-256.
pub fn hash_bytes(bytes: &[u8]) -> Digest {
    *Impl::hash_bytes(bytes)
}

#[test]
fn test_bytes_to_words() {
    let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let words = bytes_to_words(&bytes);
    let expected_bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00];
    assert_eq!(expected_bytes, words_to_bytes(&words));
}

#[test]
fn test_words_to_bytes() {
    let words = vec![0x01020304, 0x05060708];
    let bytes = words_to_bytes(&words);
    assert_eq!(words, bytes_to_words(bytes));
}
