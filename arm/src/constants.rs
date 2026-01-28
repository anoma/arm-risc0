//! Constants for compliance and padding logic proving and verification keys.

use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;

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
        Digest::from_hex("919e13001cd3319be5a5a7cb189203be083674acb3fff23d05aae9c3ed86314d")
            .unwrap();

    /// padding logic verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("21fcc2fc2c07f9753405d3070f2488c67389f7d797b6f6e20a9f2529fe4a0bff")
            .unwrap();

    /// Batch aggregation verification key / Batch aggregation image id.
    #[cfg(feature = "aggregation")]
    pub static ref BATCH_AGGREGATION_VK: Digest = Digest::from_hex("5ca0cbd4d5c267f42e0883b1ae7a28689d792230d9c4c61ca4f5df56aaf5fede").unwrap();
}
