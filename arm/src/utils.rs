//! Utility functions for byte and word conversions and hashing.

pub use arm_core::utils::{bytes_to_words, words_to_bytes};
use risc0_zkvm::sha::{Digest as Risc0Digest, Impl, Sha256, DIGEST_WORDS};

/// Hashes two digests together using SHA-256.
pub fn hash_two(left: &Risc0Digest, right: &Risc0Digest) -> Risc0Digest {
    let mut words = Vec::with_capacity(2 * DIGEST_WORDS);
    words.extend_from_slice(left.as_words());
    words.extend_from_slice(right.as_words());
    *Impl::hash_words(&words)
}

/// Hashes arbitrary bytes using SHA-256.
pub fn hash_bytes(bytes: &[u8]) -> Risc0Digest {
    *Impl::hash_bytes(bytes)
}

/// Convert arm_core::Digest to risc0_zkvm::Digest (layouts are identical: both [u32; 8]).
pub fn core_to_risc0_digest(d: &arm_core::Digest) -> risc0_zkvm::Digest {
    risc0_zkvm::Digest::new(*d.as_words())
}

/// Convert risc0_zkvm::Digest to arm_core::Digest.
pub fn risc0_to_core_digest(d: risc0_zkvm::Digest) -> arm_core::Digest {
    let words: [u32; arm_core::digest::DIGEST_WORDS] = d
        .as_words()
        .try_into()
        .expect("risc0 digest must have 8 words");
    arm_core::Digest::new(words)
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
