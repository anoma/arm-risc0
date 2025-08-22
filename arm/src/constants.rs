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
        Digest::from_hex("2c10d71e919b8b6359bfc167294c9994c1699e3eeb851d4b7775edb67b54a327")
            .unwrap();

    // padding logic verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("f8047dc2cf6cbe45137a588a3f019814218e7d7199b1b86a57b51c310e04fae9")
            .unwrap();

    // test logic verification key / compliance image id
    pub static ref TEST_LOGIC_VK: Digest =
        Digest::from_hex("14cd7fdc889b994f8bd729faa73e16d53338ed1716332b9995a5dac9e0237732")
            .unwrap();
}
