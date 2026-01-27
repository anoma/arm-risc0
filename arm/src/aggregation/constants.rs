//! Aggregation constants for proving keys and verification keys.

use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;

/// Batch aggregation proving key / batch aggregation guest ELF binary
pub const BATCH_AGGREGATION_PK: &[u8] = include_bytes!("../../elfs/batch-aggregation-guest.bin");

lazy_static! {
    /// Batch aggregation verification key / Batch aggregation image id.
    pub static ref BATCH_AGGREGATION_VK: Digest = Digest::from_hex("5ca0cbd4d5c267f42e0883b1ae7a28689d792230d9c4c61ca4f5df56aaf5fede").unwrap();
}
