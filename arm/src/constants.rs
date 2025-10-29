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
        Digest::from_hex("76fa78e83e89d15dd2ae05a6940c3ed8308476a291c2fa62af37f885587a4ab5")
            .unwrap();

    /// padding logic verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("21fcc2fc2c07f9753405d3070f2488c67389f7d797b6f6e20a9f2529fe4a0bff")
            .unwrap();
}

#[cfg(feature = "aggregation")]
lazy_static! {
    /// Batch aggregation verification key / Batch aggregation image id.
    pub static ref BATCH_AGGREGATION_VK: Digest = Digest::from_hex("8cf1a89e7d977d1024806c63797d30c5677ce8be7975d5484ffdac9acb8815b7").unwrap();
}
