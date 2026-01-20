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
        Digest::from_hex("25782c2bbe597a2db31fcce28f6cd3e1aa423f2cb987aab0e881ed87b9369d13").unwrap();

    /// Batch aggregation verification key / Batch aggregation image id.
    pub static ref BATCH_AGGREGATION_VK: Digest = Digest::from_hex("4297db7ea74c296acd49ca55e160a6e930478da2605931ea0654d466c0f95099").unwrap();
}
