use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;

// Compliance proving key / compliance guest ELF binary
pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance-guest.bin");
// Trivial logic proving key / trivial logic guest ELF binary
pub const TRIVIAL_LOGIC_PK: &[u8] = include_bytes!("../elfs/trivial-logic-guest.bin");

lazy_static! {
    // compliance verification key / compliance image id
    pub static ref COMPLIANCE_VK: Digest =
        Digest::from_hex("6be5d2af83d5cd835ebdf43d70b605f54f45e47ace8e7e578af378f85cf24701")
            .unwrap();

    // trivial logic verification key / compliance image id
    pub static ref TRIVIAL_LOGIC_VK: Digest =
        Digest::from_hex("92d124bb8aab5f9f02e978ed6db3f81b1629da09769df41bd48be915e0e2a0b6")
            .unwrap();
}
