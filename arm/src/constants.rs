use lazy_static::lazy_static;
use risc0_zkvm::Digest;
use hex::FromHex;

// Compliance proving key / compliance guest ELF binary
pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance-guest.bin");
// Padding logic proving key / padding logic guest ELF binary
pub const PADDING_LOGIC_PK: &[u8] = include_bytes!("../elfs/trivial-guest.bin");


lazy_static! {
    // compliance verification key / compliance image id
    pub static ref COMPLIANCE_VK: Digest =
        Digest::from_hex("292f133f48a8a74efaec4079554f9b33e3ef1ffb263273f0e15850dfc3799895")
            .unwrap();

    // compliance verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("d22bf61b3446db08cf1eeebbbbcdadcfd9369ff0bff8d4784a6991184546ceb8")
            .unwrap();
}