//! Constants for compliance and padding logic proving and verification keys.

use hex_literal::hex;

/// Compliance verification key bytes.
pub const COMPLIANCE_VK_BYTES: [u8; 32] =
    hex!("919e13001cd3319be5a5a7cb189203be083674acb3fff23d05aae9c3ed86314d");

/// Padding logic verification key bytes.
pub const PADDING_LOGIC_VK_BYTES: [u8; 32] =
    hex!("21fcc2fc2c07f9753405d3070f2488c67389f7d797b6f6e20a9f2529fe4a0bff");

/// Hash of the empty string (used for PADDING_LEAF and INITIAL_ROOT).
pub const EMPTY_HASH_BYTES: [u8; 32] =
    hex!("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06");

/// Compliance proving key / compliance guest ELF binary.
#[cfg(feature = "zkvm")]
pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance-guest.bin");

/// Padding logic proving key / padding logic guest ELF binary.
#[cfg(feature = "zkvm")]
pub const PADDING_LOGIC_PK: &[u8] = include_bytes!("../elfs/trivial-logic-guest.bin");

/// Batch aggregation proving key / batch aggregation guest ELF binary.
#[cfg(feature = "aggregation")]
pub const BATCH_AGGREGATION_PK: &[u8] = include_bytes!("../elfs/batch-aggregation-guest.bin");

#[cfg(feature = "zkvm")]
use lazy_static::lazy_static;

#[cfg(feature = "zkvm")]
lazy_static! {
    /// Compliance verification key as a risc0 Digest.
    pub static ref COMPLIANCE_VK: crate::Digest =
        crate::Digest::try_from(COMPLIANCE_VK_BYTES.as_slice()).unwrap();

    /// Padding logic verification key as a risc0 Digest.
    pub static ref PADDING_LOGIC_VK: crate::Digest =
        crate::Digest::try_from(PADDING_LOGIC_VK_BYTES.as_slice()).unwrap();
}

#[cfg(feature = "aggregation")]
lazy_static! {
    /// Batch aggregation verification key / Batch aggregation image id.
    pub static ref BATCH_AGGREGATION_VK: crate::Digest =
        crate::Digest::try_from(hex!("5ca0cbd4d5c267f42e0883b1ae7a28689d792230d9c4c61ca4f5df56aaf5fede").as_slice()).unwrap();
}
