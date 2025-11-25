use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;

// Compliance proving key / compliance guest ELF binary
pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance-guest.bin");
// Padding logic proving key / padding logic guest ELF binary
pub const PADDING_LOGIC_PK: &[u8] = include_bytes!("../elfs/trivial-logic-guest.bin");

lazy_static! {
    // compliance verification key / compliance image id
    pub static ref COMPLIANCE_VK: Digest =
        Digest::from_hex("90a9f98fb03385c5f0346778c57ba26578694dfa33c543bd700587ca5f789105")
            .unwrap();

    // padding logic verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("c3f7e55666d59dc58cf31582c05f0088b947310070c6c63cf03f7b15b12c4d5f")
            .unwrap();
}
