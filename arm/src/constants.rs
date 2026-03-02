//! Constants for compliance and padding logic proving and verification keys.

pub use arm_core::constants::{
    BATCH_AGGREGATION_VK_BYTES, COMPLIANCE_VK_BYTES, EMPTY_HASH_BYTES, PADDING_LOGIC_VK_BYTES,
};
use lazy_static::lazy_static;

use crate::Digest;

/// Compliance proving key / compliance guest ELF binary
pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance-guest.bin");
/// Padding logic proving key / padding logic guest ELF binary
pub const PADDING_LOGIC_PK: &[u8] = include_bytes!("../elfs/trivial-logic-guest.bin");
/// Batch aggregation proving key / batch aggregation guest ELF binary
#[cfg(feature = "aggregation")]
pub const BATCH_AGGREGATION_PK: &[u8] = include_bytes!("../elfs/batch-aggregation-guest.bin");

lazy_static! {
    /// compliance verification key / compliance image id
    pub static ref COMPLIANCE_VK: Digest =
        Digest::try_from(COMPLIANCE_VK_BYTES.as_slice()).unwrap();

    /// padding logic verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::try_from(PADDING_LOGIC_VK_BYTES.as_slice()).unwrap();
}

#[cfg(feature = "aggregation")]
lazy_static! {
    /// Batch aggregation verification key / Batch aggregation image id.
    pub static ref BATCH_AGGREGATION_VK: Digest =
        Digest::try_from(BATCH_AGGREGATION_VK_BYTES.as_slice()).unwrap();
}
