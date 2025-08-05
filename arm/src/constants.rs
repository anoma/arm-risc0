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
        Digest::from_hex("ab5a67860b67f0bc448c1ac55d71561e837601a85591581055cf80e216ddc216")
            .unwrap();

    // compliance verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("95c8992a13f68d6d969e4e1558c2aa2fdcbe05900a4f531b3b49b397e79b8a44")
            .unwrap();
}
