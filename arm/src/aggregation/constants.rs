//! Aggregation constants for proving keys and verification keys.

use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;

/// Sequential aggregation proving key / sequential aggregation guest ELF binary
pub const SEQUENTIAL_AGGREGATION_PK: &[u8] =
    include_bytes!("../../elfs/sequential_aggregation.bin");
/// Batch aggregation proving key / batch aggregation guest ELF binary
pub const BATCH_AGGREGATION_PK: &[u8] = include_bytes!("../../elfs/batch_aggregation.bin");

lazy_static! {
    /// Sequential aggregation verification key / sequential aggregation image id.
    pub static ref SEQUENTIAL_AGGREGATION_VK: Digest =
        Digest::from_hex("c5e69eb269d73d061c6ceeffe8da6eadfc3e3b48a5130979ee97a5b9aced6e4c").unwrap();

    /// Batch aggregation verification key / Batch aggregation image id.
    pub static ref BATCH_AGGREGATION_VK: Digest = Digest::from_hex("6bd39fd7673afba6dbde9e024875ebce86b93fb49a28b7d0fde61abdf2b5f2bf").unwrap();
}
