use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;

// Compliance proving key / compliance guest ELF binary
pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance_2.bin");
// Compliance var proving key / compliance guest ELF binary
pub const COMPLIANCE_VAR_PK: &[u8] = include_bytes!("../elfs/compliance_var.bin");
// Compliance sigmabus proving key / compliance guest ELF binary
pub const COMPLIANCE_SIGMABUS_PK: &[u8] = include_bytes!("../elfs/compliance_sigmabus.bin");
// Padding logic proving key / padding logic guest ELF binary
pub const PADDING_LOGIC_PK: &[u8] = include_bytes!("../elfs/trivial-logic-guest.bin");

lazy_static! {
    // compliance verification key / compliance image id
    pub static ref COMPLIANCE_VK: Digest =
        Digest::from_hex("f68d3e4ec1d37a744297eec7e5c3b1ae6051b113dde2f56a3c32bc41ee0faaa7")
            .unwrap();

    // compliance_var verification key / compliance image id
    pub static ref COMPLIANCE_VAR_VK: Digest =
        Digest::from_hex("4386dca64aafb77c602e3959f73ac12ca365ad53733a0dc04187f05a6eccd06d")
            .unwrap();

    // compliance_sigmabus verification key / compliance image id
    pub static ref COMPLIANCE_SIGMABUS_VK: Digest =
        Digest::from_hex("defcaa8da3d816351f224df9c762a382eb6ec2ff59b10534d2d9c124c3bdb5ff")
            .unwrap();

    // padding logic verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("d67cdd850ca9eb834fb0a7ca49489d88a3301ffdd31462f502280c906bffaf75")
            .unwrap();
}
