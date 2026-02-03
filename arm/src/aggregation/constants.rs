//! Aggregation constants for proving keys and verification keys.

use crate::constants::{BATCH_AGGREGATION_VK_BYTES, SEQUENTIAL_AGGREGATION_VK_BYTES};

/// Sequential aggregation proving key / sequential aggregation guest ELF binary
pub const SEQUENTIAL_AGGREGATION_PK: &[u8] =
    include_bytes!("../../elfs/sequential_aggregation.bin");
/// Batch aggregation proving key / batch aggregation guest ELF binary
pub const BATCH_AGGREGATION_PK: &[u8] = include_bytes!("../../elfs/batch_aggregation.bin");

lazy_static::lazy_static! {
    /// Sequential aggregation verification key / sequential aggregation image id.
    pub static ref SEQUENTIAL_AGGREGATION_VK: crate::Digest =
        crate::Digest::new(bytemuck::cast(SEQUENTIAL_AGGREGATION_VK_BYTES));

    /// Batch aggregation verification key / Batch aggregation image id.
    pub static ref BATCH_AGGREGATION_VK: crate::Digest =
        crate::Digest::new(bytemuck::cast(BATCH_AGGREGATION_VK_BYTES));
}
