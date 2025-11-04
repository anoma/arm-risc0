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
        Digest::from_hex("9acbebc99ed056cad5a823f7c68f03a5ff9c66bb7188346d46e5c41e75078d72")
            .unwrap();

    // padding logic verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("8c61e9baaa940beb83a7e47fe30d3dacc1c0943596262f0b530b79e5bbd505fa")
            .unwrap();
}
