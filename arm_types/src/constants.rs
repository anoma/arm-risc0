//! Constants for compliance and padding logic proving and verification keys.

use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkp::core::digest::Digest;

// /// Compliance proving key / compliance guest ELF binary
// pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance-guest.bin");
// /// Padding logic proving key / padding logic guest ELF binary
// pub const PADDING_LOGIC_PK: &[u8] = include_bytes!("../elfs/trivial-logic-guest.bin");

lazy_static! {
    /// compliance verification key / compliance image id
    pub static ref COMPLIANCE_VK: Digest =
        Digest::from_hex("0bccec1401e3bfc1b024f0c3abf520939d0166deba454b54a505582448cc97dd")
            .unwrap();

    /// padding logic verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("f48e335148e57f9cad071feb845588bf0ef43f55784f2e184439b152904446be")
            .unwrap();
}
