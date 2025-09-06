use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;

// Compliance proving key / compliance guest ELF binary
pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance-guest.bin");
// Padding logic proving key / padding logic guest ELF binary
pub const PADDING_LOGIC_PK: &[u8] = include_bytes!("../elfs/trivial-logic-guest.bin");
// Test logic proving key / test logic guest ELF binary
pub const TEST_LOGIC_PK: &[u8] = include_bytes!("../elfs/logic-test-guest.bin");

lazy_static! {
    // compliance verification key / compliance image id
    pub static ref COMPLIANCE_VK: Digest =
        Digest::from_hex("dd5f40d41c458fead76ed8bf88f46211df05786aa66eed34a28cdd8c1bac2bb7")
            .unwrap();

    // padding logic verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("7fa29b5fbb0b7b8e65345ff254623c819d34f0a855f4a20135a12320d6f8ce4d")
            .unwrap();

    // test logic verification key / compliance image id
    pub static ref TEST_LOGIC_VK: Digest =
        Digest::from_hex("f830be2a0b1ff23e5febaf6e2a52a3d2f0cac7a315a75ca2cadfd569e81f6016")
            .unwrap();
}
