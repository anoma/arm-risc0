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
        Digest::from_hex("706468196fd92568220f5271e843c608126f7a8f204205d42ceef1f2c69f91df")
            .unwrap();

    // padding logic verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("0298692ae61ee4bcc4fb6459ddde88559715f2c125530ced6d327b6e60c27cef")
            .unwrap();

    // test logic verification key / compliance image id
    pub static ref TEST_LOGIC_VK: Digest =
        Digest::from_hex("7287d95884c06ab32a2c24f677c1852c51b57504a415291429131b2e421eeefa")
            .unwrap();
}
