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
        Digest::from_hex("d93ccb46d31ce839ae75ac2e1c500d7ff0f084eb4b644cf819cd85ceb7f92af4")
            .unwrap();

    // padding logic verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("caab0963547ee75105d14c4a46b2e56c40c2e0aa9e95dcf254d514289570b8c0")
            .unwrap();

    // test logic verification key / compliance image id
    pub static ref TEST_LOGIC_VK: Digest =
        Digest::from_hex("e97ff992ff771b03827f310b3e442d1aa6072465561c9ca54a34635ca67e83f0")
            .unwrap();
}
