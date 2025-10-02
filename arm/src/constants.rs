use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;

// Compliance proving key / compliance guest ELF binary
pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance_2.bin");
// Compliance proving key / compliance guest ELF binary
pub const COMPLIANCE_VAR_PK: &[u8] = include_bytes!("../elfs/compliance_var.bin");
// Padding logic proving key / padding logic guest ELF binary
pub const PADDING_LOGIC_PK: &[u8] = include_bytes!("../elfs/trivial-logic-guest.bin");

lazy_static! {
    // compliance verification key / compliance image id
    pub static ref COMPLIANCE_VK: Digest =
        Digest::from_hex("86f2d0445e3d7cc870059f2f41d3eb154ad323f84c631345e9b6443dc8157473")
            .unwrap();

    // compliance_var verification key / compliance image id
    pub static ref COMPLIANCE_VAR_VK: Digest =
        Digest::from_hex("c12525e31c52a8f83988b3f64a4172d0dbd2c2de91fc782bd92ff8179a72aa17")
            .unwrap();

    // padding logic verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("d67cdd850ca9eb834fb0a7ca49489d88a3301ffdd31462f502280c906bffaf75")
            .unwrap();
}
